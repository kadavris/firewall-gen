# firewall-gen
 iptables multi-interface firewall generator/builder  
 Uses perl5

## Features:
* Class/profile-based access configuration with inheritance
* MAC access filters.
* Per-device access rules.
* Default network-wide settings for unknown devices, like Wi-Fi guest clients
* Pre-filters for common attack types with or without logging
* Multiple networks/IPs support per interface
* One optional, fixed-purpose interface - Internet connection
* Unlimited secondary physical interfaces
* Unlimited virtual interfaces for containers, etc.  
  With in/out access settings
* Pre-flight checks of configuration
* Probably some more...

## how to start
* Look into `firewall4-gen.conf.sample` for complete description and example.
* Make your own `firewall4-gen.conf`.  
  *This is the default name for configuration file.*
* Run `firewall4-gen.pl`
* Check output for error messages.
* Check created file for problems.
* Run `iptables-restore -v < your_file`  
  *See `$save_file` variable in .config*

---
# Remember that applying firewall rules while being on remote connection **may drop you out** if problem occur!

## Configuration and features in details:

Only `iptables` configuration is supported right now.

Use `-t` switch to produce test output to STDERR

The basic packet processing scheme is:
1) from `INPUT` -> jump to `XXX_in` chain for each interface
2) check for common problems
3) if there are `%access` entries defined:  
  Match `MAC` to `IP`  
  goto #4  
  `DROP` otherwise.
4) Using separate chain for each client, check packet according to its `class profile` and do `ACCEPT` or `DROP`.
5) `ACCEPT` or `DROP` as set by **default** access class

---
## .conf file:

For simplicity reasons, config file is pure perl that is included as code at the runtime.

Nearly all lists are `hashes`, meaning *key* `=>` *value* containers.

### `%tables` - iptables' tables and default chains settings (`INPUT`, `OUTPUT`, etc)
At the top level there are tables configuration:  
For `filter` table this we have 3 entities:
* `common chains` - defining the naming scheme for chains
* `defaults` - set default targets (`ACCEPT` or `DROP`) for each of top-level chains: `INPUT`, `OUTPUT`, `FORWARD`

For `nat` table we have:
* `defaults` - set default targets (`ACCEPT` or `DROP`) for each of top-level chains: `INPUT`, `OUTPUT`, `FORWARD`, `PREROUTING`, `POSTROUTING`

### Access classes:
This stuff define profiles or common access parameters for hosts, nets or interfaces.  
Classes are not interface-bound, so they can be used everywhere.
The scheme is:

        'class name' => [ 'parent class or empty', 'option1', ..., 'optionN' ],
e.g.

      'simple host' => [ '', 'dhcp', 'i-net' ]
Define class `simple host` and allow incoming `DHCP` requests to **this host**. And `i-net` makes it able to go to the Big Net.  
And there are

      'lan client' => [ 'simple host', 'samba' ]
      'wifi client' => [ 'simple host', 'logdrop' ]

So our `lan client` being on secure network is permitted to use `samba` service.  
And `wifi client` from guest network can freely use Internet, but any attempt to peek into server's interface will result in log and DROP.

Options for enabling services:
* `bootp` - add bootstrap ports (implies dhcp)
* `dhcp` - DHCP access
* `i-net[:dst1,dst2...]` - allows outgoing connections to internet hosts/nets
* `samba` - samba support for incoming connections
* `rtsp` - may enable specifics for this to work

Options for intrusion detection:
* `(drop|log) bad tcp` - adds rules to check for common malformed tcp packets used in hacks and scans
* `(allow|deny)to:addr[:proto:portlist[;...]]` - used with `quarantine` option to enable/disable some additional stuff
* `limit scans` - limit icmp pings and tcp probes to advised level
* `logdrop[:portlist]` - for close monitored nets - log all packet drops. default portlist is 0-1023

Options for restricting access:
* `norestrict` - no particular filtering applied, except general rules in the generator script.
* `quarantine[:addr:proto:portlist;...]` - close all or specified DESTINATION ports

protocol:portlist option:
* when standalone (not used as a modifier for other statement like `quarantine`):
   - if set within host/network class - allow _incoming to server's matching ip_ by whis protocol and ports.
   - if set inside of **interface's** own class - allow _OUTGOING_ from this interface.
* when used as a modifier for some other option like `allowto`/`denyto` - act according to option's direction of access

Known protocols:

      all|any|bcast|icmp|tcp|udp  

portlist is:

      +|-|*|port range[,port range...]

where:
* `+` - **allow** all in or out (depending on where this class used: host/net or interface),
* `-` = **block** all in or out,
* `*` - relaxed access to _server's_ interface. No sense to use as interface's class, which is output type
* `port range` - `port name`|`port number`[:`port number`]

Multiple, entries for a single protocol are allowed.  
When there is '!' used before the port, the inverse meaning is applied (almost implemented!)  
Note: `bcast` uses 224.0.0.0/4 and 240.0.0.0/4 nets as destination.

---
### Interfaces/nets:
Current scheme uses 2 hardcoded names:
* `inet` - internet. Optional.
* `lan`  - local, secure network.

The `init()` procedure will run `ip a` to append/check actual interface data to each of the root keys.
E.g. the `$lan` hash will be like:
 
      if = 'enp0s31f6'
      default = 0     -- is this a default route?
      gw = 'x.x.x.x'  -- if this if is default then this is gateway's IP
      type = 'ether'
      up = 1    -- interface is up?
      ipX addr[]  = '10.1.1.1'    -- IPs
      ipX bcast[] = '10.1.1.255'  -- broadcasts
      ipX mask[]  = 24            -- masks
      ipX net[]   = '10.1.1.0/24' -- networks
      ipX default class - default for unlisted network clients to access this interface
      ipX interface class - interface's own class. Used mainly for outgoing-quarantined virtual containers, etc...

`access` sub-tree format:
??????????
      'host/ip' => [ 'MAC address', 'allowed TCP ports list', 'allowed UDP ports list', 'allowed ICMP ports list' ]

'+' in ports list means no restrictions to any internal address, '*' - relaxed only to server's if, '-'|'' - drop all

'options' hash with default values (see $interface_default_options in code):
   'enabled' => 1 # interface is enabled
   'volatile' => 0 # interface may not be present at the generation phase. no rules made for it. use with caution

%net_interfaces = ( # root keys: lan,inet,wifi,sec - are hardcoded names!
  'lan' => {
      'mac' => 'xx:xx:xx:xx:xx:xx', # server-side
      'chains'       => { 'in' => 'lan_in', 'out' => '' },  # main chain name in iptables
      'ip4 addr'     => [ '10.1.1.1',    '10.90.90.9'   ],  # 'ip4 *' - all array must be fiiled
      'ip4 bcast'    => [ '10.1.1.255',  '10.90.90.255' ],
      'ip4 mask'     => [ 24,            24 ],
      'ip4 net'      => [ '10.1.1.0/24', '10.90.90.0/24' ],
      'ip4 default class'   => [ 'net trusted', 'net un-trusted' ],
      'ip4 interface class' => [ 'iface trusted', 'iface trusted' ],
      'access' => {
           'hosts' => {
               'dlink-switch' => [ 'xx:xx:xx:xx:xx:xx', 'net switch' ],
           },
      },
  },

  # -------------------------------------
  'inet' => {
      'mac' => 'xx:xx:xx:xx:xx:xx', # MAC here is still a formality
      'chains'       => { 'in' => 'inet_in', 'out' => '' }, # chains names
      'ip4 addr'     => [ 'your inet ip' ],
      'ip4 bcast'    => [ 'X.Y.Z.255' ],  # this and below is redundant, but used to cross-check with "ip a" for obvious errors
      'ip4 mask'     => [ 24 ],
      'ip4 net'      => [ 'x.y.z.0/24' ],

      'incoming reject' => { # REJECT these.
         # Format of keys: 'proto:method', where proto is tcp,udp. method is --reject-with argument
         # The logic behind overlapping ranges is that you may want to see attempts statistics for some separate ports
         #   So write your rules down from more specific to more broad-ranged

        'tcp:tcp-reset' => [
           'ftp,ftp-data', 'ssh,telnet', 'smtp,urd,pop3,imap,imap3,imaps,pop3s',
           'domain,domain-s', 'http,https', '137:139', 'rtsp',
           '0:1023'
        ],

        'udp:icmp-port-unreachable' => [
           'domain,domain-s',
           '0:1023',
           '0:65535'
        ]
      },

      # for incoming* stuff the list is in [addr:]port[,port...] format
      'incoming open'      => { # ports to freely open for incoming
         'tcp' => [ 'someport', '12345' ],
         'udp' => [  ]
      },
      'incoming open & log'  => { # ports to open AND LOG (tcp is setup only)
         'tcp' => [ 'X.X.X.X:23', 'Y.Y.Y.0/24:23' ],
         'udp' => [] # allow SSH from some
      },
      'incoming block & log' => { # _closed_ ports to LOG on attempt
         'tcp' => [], 'udp' => []
      },

      'silent drop list' => [ # this is dst ips:ports that we drop silently from the START.
         # NOTE: @cross_drop_list with both -s and -d added here automatically
         '*:137',
         '*:138',
         '*:1900',
         '*:1997',
         '*:3702',
         '*:7680',
         '*:8083'
      ], # silent drop
  },

  # -------------------------------------
  # A cable to access point. insecure by design
  # keep key names short - it is used as parts of rule names
  'wifi' => {
      'mac' => 'xx:xx:xx:xx:xx:xx', # interface MAC
      'name' => 'Wi-Fi', # name to display
      'chains' => { 'in' => 'wifi_in', 'out' => '' },

      # for ip4* multiple addresses supported
      'ip4 addr'            => [ '192.168.0.2',          '192.168.1.2',     '192.168.2.2'   ],
      'ip4 bcast'           => [ '192.168.255.255',      '192.168.255.255', '192.168.255.255' ],
      'ip4 mask'            => [ 16,                     16,                16 ],
      'ip4 net'             => [ '192.168.0.0/16',       '192.168.0.0/16',  '192.168.0.0/16' ],
      # 
      'ip4 default class'   => [ 'wifi net',             'wifi restricted', 'wifi restricted' ],
      'ip4 interface class' => [ 'iface trusted',        'iface trusted',   'iface trusted' ],

      'silent drop list' => [ # this is stuff that we drop at the END and silently.
         '224.0.0.0/4', # 224.0.0.0 ~ 239.255.255.255 reserved for multicast addresses. RFC 3171
         '240.0.0.0/4', # reserved (former Class E network) RFC 1700
         '255.255.255.255', # is the limited broadcast address (limited to all other nodes on the LAN) RFC 919
         '*:1900',
         '*:1997',
         '*:5555',
         '*:3702',
         '*:7680',
         '*:8083'
      ], # silent drop

      'access' => {
         'hosts' => {
           # you can add overlay/override configuration if you do not want to make new class for single device:
           'some-notebook' =>   [ 'xx:xx:xx:xx:xx:xx', 'wifi known pc', 'tcp:some additional ports', 'some overrides here too' ... ],

           'server-to-wifi' =>  [ 'xx:xx:xx:xx:xx:xx', 'iface trusted' ], # own intf
           'somephone' =>       [ 'xx:xx:xx:xx:xx:xx', 'wifi known gadget' ],
           'some-tablet' =>     [ 'xx:xx:xx:xx:xx:xx', 'wifi known gadget' ],
           'vacuum' =>          [ 'xx:xx:xx:xx:xx:xx', 'wifi smarthome' ],
           'wifi-router' =>     [ 'xx:xx:xx:xx:xx:xx', 'net switch' ], # Access point itself
           'smartcam1' =>       [ 'xx:xx:xx:xx:xx:xx', 'wifi cam' ],
           'smarthub' =>        [ 'xx:xx:xx:xx:xx:xx', 'wifi smarthome hub' ],
           'smartplug1' =>      [ 'xx:xx:xx:xx:xx:xx', 'wifi smarthome' ],
       }, #access/hosts
    },
  }, # wifi

  # -------------------------------------
  # another ethernet for security/surveillance stuff. insecure too (chinese cameras seeking master's commands, ye know)
  'sec'  => {
      'mac' => 'xx:xx:xx:xx:xx:xx',
      'name' => 'Security',
      'chains'       => { 'in' => 'sec_in', 'out' => '' },
      'ip4 addr'     => [ '10.1.2.1', ],
      'ip4 bcast'    => [ '10.1.2.255' ],
      'ip4 mask'     => [ 24 ],
      'ip4 net'      => [ '10.1.2.0/24' ],
      'ip4 restrict' => [ 0 ],
      'ip4 default class' => [ 'sec default' ],
      'ip4 interface class' => [ 'iface trusted' ],

      'access' => {
           'hosts' => {
              'ip-cam-1'    => [ 'xx:xx:xx:xx:xx:xx', 'sec cam' ],
              'ip-cam-2'    => [ 'xx:xx:xx:xx:xx:xx', 'sec cam' ],
              'sec mon hub' => [ 'xx:xx:xx:xx:xx:xx', 'sec mon vendor' ],
           }, #access/hosts
      },

      'silent drop list' => [ # this is stuff that we drop at the START and silently.
         '*:53', # DNS is unnecessary here
         '*:80', # some upnp-like stuff happens
      ], # silent drop
  }, # sec

  # -------------------------------------
  'hassio' => { # Home Assistant in container
      'mac' => '', # no MAC means virtual
      'options' => { 'volatile' => 1 },
      'chains'       => { 'in' => 'hassio_in', 'out' => 'hassio_out' },
      'rules func'   => \&virtual_rules, # dirty hack to implement different approach for specific networks
      'ip4 addr'     => [ '172.30.32.1' ],
      'ip4 bcast'    => [ '172.30.33.255' ],
      'ip4 mask'     => [ 23, ],
      'ip4 net'      => [ '172.30.32.0/23' ],
      'ip4 default class'   => [ 'net hassio' ],
      'ip4 interface class' => [ 'iface hassio' ],

      'silent drop list' => [ # this is stuff that we drop at the END and silently.
        # empty
      ], # silent drop

      'access' => {
         'hosts' => {
           # empty
         }
      }, #access/hosts
  }, # hassio


  # -------------------------------------
  #7: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  #  link/ether 02:42:b2:60:b0:e8 brd ff:ff:ff:ff:ff:ff
  #  inet 172.17.0.1/16 scope global docker0
  #     valid_lft forever preferred_lft forever
  'docker0' => { # docker's own interface
      'mac' => '', # no MAC means virtual.
      'name' => 'docker',
      'options' => { 'volatile' => 1 }, # volatile means that interface may not be present at the generation phase. use with caution
      'chains'       => { 'in' => 'docker0_in', 'out' => 'docker0_out' },
      'rules func'   => \&virtual_rules,
      'ip4 addr'     => [ '172.17.0.1' ],
      'ip4 bcast'    => [ '172.17.255.255' ],
      'ip4 mask'     => [ 16, ],
      'ip4 net'      => [ '172.17.0.0/16' ],
      'ip4 restrict' => [ 0 ],
      'ip4 default class'   => [ 'net docker' ],
      'ip4 interface class' => [ 'iface docker' ],

      'silent drop list' => [ # this is stuff that we drop at the END and silently.
           # empty
      ], # silent drop

      'access' => {
         'hosts' => {
           # empty
         }
      }, #access/hosts
  }, # docker0
);

# this is the list of nets which are by default will be DROPped on access from other nets
# hard anti-spoof feature.
# used in sub drop_destinations() that somewhat smartly allow internal traffic to flow still
@cross_drop_list = ( # wiki: https://en.wikipedia.org/wiki/Reserved_IP_addresses
  '0.0.0.0/8',           # 0.0.0.0�0.255.255.255       Software    Current network[1] (only valid as source address).
  '10.0.0.0/8',          # 10.0.0.0�10.255.255.255     Private network     Used for local communications within a private network.[2]
  '100.64.0.0/10',       # 100.64.0.0�100.127.255.255  Private network     Shared address space[3] for communications between a service provider and its subscribers when using a carrier-grade NAT.
  '127.0.0.0/8',         # 127.0.0.0�127.255.255.255   Host    Used for loopback addresses to the local host.[1]
  '169.254.0.0/16',      # 169.254.0.0�169.254.255.255 Subnet  Used for link-local addresses[4] between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server.
  '172.16.0.0/12',       # 172.16.0.0�172.31.255.255   Private network     Used for local communications within a private network.[2]
  '192.0.0.0/24',        # 192.0.0.0�192.0.0.255       Private network     IETF Protocol Assignments.[1]
  '192.0.2.0/24',        # 192.0.2.0�192.0.2.255       Documentation   Assigned as TEST-NET-1, documentation and examples.[5]
  '192.88.99.0/24',      # 192.88.99.0�192.88.99.255   Internet    Reserved.[6] Formerly used for IPv6 to IPv4 relay[7] (included IPv6 address block 2002::/16).
  '192.168.0.0/16',      # 192.168.0.0�192.168.255.255 Private network     Used for local communications within a private network.[2]
  '198.18.0.0/15',       # 198.18.0.0�198.19.255.255   Private network     Used for benchmark testing of inter-network communications between two separate subnets.[8]
  '198.51.100.0/24',     # 198.51.100.0�198.51.100.255 Documentation   Assigned as TEST-NET-2, documentation and examples.[5]
  '203.0.113.0/24',      # 203.0.113.0�203.0.113.255   Documentation   Assigned as TEST-NET-3, documentation and examples.[5]
  '224.0.0.0/4',         # 224.0.0.0�239.255.255.255   Internet    In use for IP multicast.[9] (Former Class D network).
  '240.0.0.0/4',         # 240.0.0.0�255.255.255.254   Internet    Reserved for future use.[10] (Former Class E network).
  #'255.255.255.255/32',  # 255.255.255.255            Subnet  Reserved for the "limited broadcast" destination address.[1][11]
);
