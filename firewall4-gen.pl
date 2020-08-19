#!/bin/perl
use strict;
use warnings;
use Carp;
use Getopt::Long;
use Storable qw(dclone); # deep clone used to init access class with parent's data

my $default_if; # default route interface ref. used for making right forwards.
my %net_interfaces; #main interfaces config
my $save_file; # rules output file
my @silent_drop_by_dst; # destinations to drop always
my @cross_drop_list; # default destinations to drop between interfaces

my %tables; # tables config
my %classes; # access rules

my $debug = 0;
my $verboseness = 1; # at zero show minimal info needed to confirm what's done

my $errors_count;   # will not load new config if any
my $warnings_count; # da same

my $interface_default_options = {
  'enabled' => 1,
  'volatile' => 0,
};

my $cfg = 'firewall4-gen.conf';

my $version = '1.5';

##########################################################
print "Firewall rules generation tool. V$version\nMade my Andrej Pakhutin (pakhutin<at>gmail)\n";
print "Repository is at https://github.com/kadavris\n";

GetOptions(
  'd' => \$debug,
  'v=i' => \$verboseness,
);

if( $#ARGV > -1 )
{
  if( ! -r $ARGV[0] )
  {
    print "$ARGV[0] is unreadable. Supply non-default config name as a parameter\n";
    exit(1);
  }

  $cfg = $ARGV[0];
}

open C, $cfg  or die "$cfg: $!";
sysread( C, $cfg, 999999 ) or die "config is empty?";
eval $cfg or croak "config: $@";
close C;

print "Config interfaces found: ", join( ', ', keys %net_interfaces ), "\n";

my $current_table; # filter/nat,etc - iptables current table name for @chains
my $common_chains; # ref to common chains hash of the current table
my %chains; # used to sanity-check rule output and creation fmt: tablename:chainname - e.g. filter:INPUT

# the init() proc will append/check actual interface data to each of the root keys.
# e.g. the $lan hash will be like:
#     if = 'enp0s31f6'
#     default = 0     -- is this a default route?
#     gw = 'x.x.x.x'  -- if this if is default then this is gateway's IP
#     type = 'ether'
#     up = 1    -- interface is up?
#     ipXaddr[]  = '10.1.1.1'    -- IPs
#     ipXbcast[] = '10.1.1.255'  -- broadcasts
#     ipXmask[]  = 24            -- masks
#     ipXnet[]   = '10.1.1.0/24' -- networks
#     ipXrestrict = 0  -- restrict activity to server interface only
# access sub-tree format:
#    'host' => [ 'mac', 'tcp ports list', 'udp ports list', 'icmp ports list' ]
#    '+' in ports list means no restrictions to any internal address, '*' - relaxed only to server's if, '-'|'' - drop all

init(); # pre-fill some names and addresses for simpler configuration

# make shortcuts
my $lan  = $net_interfaces{ 'lan'  }; # This interface is assumed to be most secure and trusted.
my $inet = $net_interfaces{ 'inet' }; # internet. if any

my $out_file;
open $out_file, '>', $save_file or die "$save_file: $!";

######################################
table_start( 'filter' );

######################################
######################################
# common chains

##################################
##################################
put_comment( 'INPUT', 'common stuff' );
addto( 'INPUT', '-i lo -j ACCEPT' ); # allmighty 127.0.0.1
make_log_chains('INPUT', 'b');

make_log_chains( 'FORWARD', 'b' );
addto( 'FORWARD', '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );

put_comment( 'OUTPUT', 'OUTPUT chain');
addto( 'OUTPUT', '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );

##################################
##################################
if ( $inet )
{
  $inet->{ 'options' } = make_complete_set( $inet->{ 'options' }, $interface_default_options, 1 );

  if ( $inet->{ 'options' }->{ 'enabled' } )
  {
    $default_if != $inet and croak "deafult route is not via inet interface!";

    inet_rules( 'inet' );
  }
  else
  {
    print "\n>>> NOTE: inet interface IS DISABLED and default is going via " . $default_if->{ 'alias' } . "\n\n";
  }
}
else
{
  if ( $default_if )
  {
    print "\n>>> NOTE: inet interface is undefined and default is going via " . $default_if->{ 'alias' } . "\n\n";
  }
  else
  {
    print "\n>>> NOTE: NO DEFAULT ROUTE.\n\n";
  }
}
# END: inet

for my $ifkey ( sort( keys %net_interfaces ) ) # construct other interfaces rules. make it diff-friendly
{
  if ( $ifkey eq 'inet' )
  {
    next;
  }

  my $if = $net_interfaces{ $ifkey };

  $if->{ 'options' } = make_complete_set( $if->{ 'options' }, $interface_default_options, 1 );

  if( ! $if->{ 'options' }->{ 'enabled' } )
  {
    print "\n- Skipping disabled: ", $if->{ 'alias' }, '/', $if->{ 'if name' },"\n\n";
    next;
  }

  if ( $if->{ 'mac' } ne '' )
  {
    print "+ Adding generic physical: ", $if->{ 'alias' }, '/', $if->{ 'if name' },"\n";
    generic_physical_rules( $ifkey, $if );
  }
  else
  {
    print "+ Adding virtual: ", $if->{ 'alias' }, '/', $if->{ 'if name' }, "\n";
    $if->{ 'rules func' }->( $if );
  }
}

################################
################################
# finishing touches

# silently drop some stuff on forward:
for my $n ( qw~224.0.0.0/4 240.0.0.0/4~ )
{
  add_hostport_to( 'FORWARD', '-d', $n, '-j DROP' );
}

addto( 'FORWARD', '-j FORWARD_log_drop' ); # for un-specific drops

table_flush(); # end of *filter

################################
################################
table_start( 'nat' );

# this stuff is mostly filled in *filter

# some poor man's transparent proxy:
for my $addr ( qw~ip/mask:port~ )
{
  my $port = 80;
  my $a = $addr;
  if ( $addr =~ /^([^:]+):(.+)$/ )
  {
    $a = $1;
    $port = $2;
  }

#  addto( 'PREROUTING', '-p tcp -m tcp --dport', $port, '-d', $a, '-j DNAT --to-destination XXXX ' );
}

table_flush();

###############################
###############################

close $out_file;

###############################################################################
###############################################################################
###############################################################################
###############################################################################
# in: name of the key in settings. used for multiple inet interfaces
sub inet_rules
{
  my $key_name = $_[0];
  my $if = $net_interfaces{ $key_name };

  $if->{ 'default' } or croak "inet interface is not the default route!";

  my $chain;

  my $chain_in = $if->{ 'chains' }->{ 'in' };
  make_chain( 'INPUT', $chain_in, '************ I-net (' . $key_name . ')***********' );

  make_log_chains( $key_name, 'b' );

  my $ip  = $if->{ 'ip4 addr' }->[0];
  my $net = $if->{ 'ip4 net' }->[0];

  # block/reject obvious scans and some malformed stuff. No logging from i-net.
  # split by portranges for statistical purposes
  my $scans_chain = 'inet_scans';

  make_chain( $chain_in, $scans_chain );

    for my $key ( keys %{ $if->{ 'incoming reject' } } )
    {
      my ( $proto, $method ) = split( ':', $key );

      for my $ports ( @{ $if->{ 'incoming reject' }->{ $key } } )
      {
        addto( $scans_chain, '-p', $proto, '-m multiport --dports', $ports, '-j REJECT --reject-with', $method );
      }
    }

  for my $n ( drop_destinations() )
  {
    addto( $chain_in, '-s', $n, '-j DROP' );
    addto( $chain_in, '-d', $n, '-j DROP' );
  }

  $chain = 'inet_silent_drop';
  make_chain( $chain_in, $chain );

  for my $n ( @{ $if->{ 'silent drop list' } } )
  {
    add_hostport_to( $chain, '-d', $n, '-j DROP' );
  }

  addto( $chain_in, '-j', $chain );

  # placed here to possibly prevent some weird spoofs that may be seen as existing connections
  addto( $chain_in, '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );

  # -- SPECIALS --
  for my $category ( ( 'incoming open', 'incoming open & log', 'incoming block & log' ) )
  {
    for my $proto ( qw~tcp udp~ )
    {
      my $list = $if->{ $category }->{ $proto };
      next if $#$list == -1; # no specifics

      for my $hp ( @$list )
      {
        my ($addr, @portlist );

        $hp =~ /^([^:]+)(:(.+))?$/;
        if ( defined( $2 ) )
        {
          $addr = '-s ' . $1;
          @portlist = split( ',', $3 );
        }
        else
        {
          $addr = '';
          @portlist = split( ',', $1 );
        }

        for my $port ( @portlist )
        {
          if ( $category eq 'incoming log' ) # log and ACCEPT
          {
            addto( $chain_in, $addr, '-p', $proto, '--dport', $port, $proto eq 'tcp' ? '-m conntrack --ctstate NEW' : '', '-j', $if->{ 'oklog chains' }->{ 'in' } );
          }
          elsif ( $category eq 'incoming note' ) # LOG and DROP
          {
            addto( $chain_in, $addr, '-p', $proto, '--dport', $port, '-j', $if->{ 'droplog chains' }->{ 'in' } );
          }
          else # open as is
          {
            addto( $chain_in, $addr, '-p', $proto, '--dport', $port, $proto eq 'tcp' ? '-m conntrack --ctstate NEW' : '', '-j ACCEPT'  );
          }
        } # portlist
      } # addr:port
    } # proto
  } # category

  # log new ssh sessions just in case
  #log_it( $chain_in, 'in-OK', 'ACCEPT', '-d', $ip, '-p tcp --dport 7273 -m conntrack --ctstate NEW' );

  #addto( $chain_in, '-d', $ip, '-p icmp --icmp-type  8', '-m limit --limit 1/m -j ACCEPT' );
  #addto( $chain_in, '-d', $ip, '-p icmp --icmp-type 11', '-m limit --limit 1/m -j ACCEPT' );

  # -- end of SPECIALS --

  #addto( $chain_in, '-m set --match-set droplist_by_port src -j DROP' );
  #addto( $chain_in, '-m set --match-set droplist_by_ip src   -j DROP' );

  # here, after per-port loggers
  my $bad_tcp_chain = 'inet_badtcp';
  make_chain( $chain_in, $bad_tcp_chain );
  make_bad_tcp_rules( $chain_in, $bad_tcp_chain );
  addto( $chain_in, '-j', $bad_tcp_chain );

  addto( $chain_in, '-p tcp --tcp-flags SYN,ACK,FIN,RST RST -j', $scans_chain );
  addto( $chain_in, '-p udp -j', $scans_chain );

  addto( $chain_in, '-j DROP' ); # all other to hell. Better leave it here to close most insecure hole

  addto( 'INPUT', '-i', $if->{ 'if name' }, '-j', $chain_in );

  # cutting runaway specials:
  for my $a ( @cross_drop_list )
  {
    addto( 'OUTPUT', '-o', $if->{ 'if name' }, '-s', $a, '-j DROP' );
    addto( 'OUTPUT', '-o', $if->{ 'if name' }, '-d', $a, '-j DROP' );
  }
} # inet_rules()

###############################################################################
# in: if key name, if hashref
sub generic_physical_rules
{
  my ( $ifkey, $if ) = @_;

  my ( $ip, $net ) = ( $if->{ 'ip4 addr' }->[0], $if->{ 'ip4 net' }->[0] );

  my $chain_in = $if->{ 'chains' }->{ 'in' };
  make_chain( 'INPUT', $chain_in, '************ ' . $if->{ 'if name' } . ' ***********' );

  make_log_chains( $ifkey, 'b' );

  log_it( $chain_in, '-INV', 'DROP', '-m conntrack --ctstate INVALID' );
  addto( $chain_in, '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );

  # this is the kind of stuff we don't want to be in the log
  my $chain = $ifkey . '_silentdrop';
  make_chain( $chain_in, $chain );
    addto( $chain_in, '-j', $chain );

    for my $n ( @{ $if->{ 'silent drop list' } } )
    {
      add_hostport_to( $chain, '-d', $n, '-j DROP' );
    }

  add_access_rules( $if );

  addto( $chain_in, '-j', $if->{ 'droplog chains' }->{ 'in' } ); # we want to see what's going on there

  addto( 'INPUT', '-i', $if->{ 'if name' }, '-j', $chain_in );
}

###############################################################################
# common rules for the virtual interfaces
# in: interface ref
sub virtual_rules
{
  defined( $_[0] ) or croak "virtual_rules() call without if hashref!";

  my $if = $_[0];
  my $chain_in  = $if->{ 'chains' }->{ 'in' };
  my $chain_out = $if->{ 'chains' }->{ 'out' };

  if ( $chain_in ne '' )
  {
    make_chain( 'INPUT', $chain_in, '********* Virtual: ' . $chain_in . ' *******' );
    addto( $chain_in, '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );
    log_it( $chain_in, '-INV', 'DROP', '-m conntrack --ctstate INVALID' );

    #for my $n ( @{ $if->{ 'silent drop list' } } )
    #{
    #  add_hostport_to( $chain_in, '-d', $n, '-j DROP' );
    #}
  }

  if ( $chain_out ne '' )
  {
    make_chain( 'OUTPUT', $chain_out, '********* Virtual: ' . $chain_out . ' *******' );
    addto( $chain_out, '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' );
    log_it( $chain_out, '-INV', 'DROP', '-m conntrack --ctstate INVALID' );

    #for my $n ( @{ $if->{ 'silent drop list' } } )
    #{
    #  add_hostport_to( $chain_out, '-d', $n, '-j DROP' );
    #}
  }

  make_log_chains( $if->{ 'alias' }, 'b' );

  for my $n ( @{ $if->{ 'silent drop list' } } )
  {
    add_hostport_to( $chain_in, '-d', $n, '-j DROP' );
  }

  add_access_rules( $if );

  # finalizing
  if ( $chain_in ne '' )
  {
    addto( 'INPUT', '-i', $if->{ 'if name' }, '-j', $chain_in );
  }

  if ( $chain_out ne '' )
  {
    addto( 'OUTPUT', '-o', $if->{ 'if name' }, '-j', $chain_out );
  }
}

###############################################################################
############  Service procedures starting from here ###########################
###############################################################################

# in: parent chain, bad rules chain
sub make_bad_tcp_rules
{
  my ( $parent, $chain, $log ) = @_;
  $log //= 0;

  my @list = (
    # 'rule', '-j somewhere (if not -j DROP as default)', 'special log rule or empty' ]
    [ '-p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW', '-j REJECT --reject-with tcp-reset', '' ],

    # New and not SYN
    [ '-p tcp ! --syn -m conntrack --ctstate NEW', '', '-p tcp ! --syn -m conntrack --ctstate NEW -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Syn"' ],

    # Null packets are, simply said, recon packets. The attack patterns use these to try and find out weaknesses.
    [ '-p tcp --tcp-flags ALL NONE', '', '-p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"' ],

    #In brief, we need to drop bogus packets, such as with SYN+FIN flags set. you can drop this particular packet by adding rule
    [ '-p tcp --tcp-flags SYN,FIN SYN,FIN', '', '' ],
    [ '-p tcp --tcp-flags SYN,RST SYN,RST', '', '' ],
    [ '-p tcp --tcp-flags ALL FIN,URG,PSH', '', '' ],
    [ '-p tcp --tcp-flags ALL ALL', '', '' ],

    # Fragments. reporting just some to not overload log
    [ '-f', '', '-f -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"' ],

    # XMAS. reporting just some to not overload log
    [ '-p tcp --tcp-flags SYN,FIN SYN,FIN', '', '-p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"' ],

    # FIN packet scans. reporting just some to not overload log
    [ '-p tcp --tcp-flags FIN,ACK FIN', '', '-p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"' ],

    [ '-p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG', '', '' ],
  );

  for my $rule ( @list )
  {
    if ( $log )
    {
      if ( $rule->[ 2 ] ne '' )
      {
        addto( $chain, $rule->[ 2 ] );
      }
      else
      {
        addto( $chain, $rule->[ 0 ], '-j LOG --log-level 4 --log-prefix "' . $parent . ':"' );
      }
    }

    addto( $chain, $rule->[ 0 ], ( $rule->[ 1 ] ne '' ? $rule->[ 1 ] : '-j DROP' ) );
  }
}

###############################################################################
# will dup rule for every of input array element. Usually for IPs/ports list
# params: [ [], []... ] - array of arrayrefs ;), addto() args
# > use %1, %2, etc signs as a placeholders for each arrayref
sub dup_rule
{
  my $refs = shift @_;
  my $chain = shift @_;
  my $tpl = join ' ', @_;

  for my $argno ( 0..$#$refs ) # finding next %x number to process
  {
    my $list = $refs->[ $argno ];
    next if ! defined $list;

    $refs->[ $argno ] = undef; # set our mark

    my $ph = '%' . ( $argno + 1 ); # get our placeholder right

    for my $elem ( @$list )
    {
      my $s = $tpl;
      $s =~ s/$ph/$elem/g;

      if ( $argno == $#$refs ) # is we're last in chain?
      {
        addto( $chain, $s ); # yep. done here
      }
      else
      {
        dup_rule( $refs, $chain, $s );
      }
    }
  }
}

###############################################################################
# will dup address/proto/ports rules for every of input hash element
# params: { { adress }->{ proto }->[ ports ] } hashref, addto() args
# > use %1, %2, %3 as a placeholders
sub dup_app_rules
{
  my $hash = shift @_;
  my $chain = shift @_;
  my $tpl = join ' ', @_;

  for my $addr ( keys %$hash )
  {
    my $addr_hash = $hash->{ $addr };

    my $tpl_a = $tpl;
    $tpl_a =~ s/%1/$addr/g;

    for my $proto ( keys %$addr_hash )
    {
      my $ports = $addr_hash->{ $proto };
      my $tpl_proto = $tpl_a;

      if ( length( $proto ) > 1 ) # ! *
      {
        $tpl_proto =~ s/%2/$proto/g;
      }
      else
      {
        $tpl_proto =~ s/\S+\s+%[23]//g; # eliminate proto/port statement(s)
        addto( $chain, $tpl_proto ); # yep. done here
        next;
      }

      for my $port ( @$ports )
      {
        my $s = $tpl_proto;

        if ( length($port) > 1 ) # not a wildcard
        {
         $s =~ s/%3/$port/g;
        }
        else
        {
          $s =~ s/\S+\s+%3//g; # eliminate port statement
        }

        addto( $chain, $s ); # yep. done here
      } # port
    } # proto
  } # addr
}

##########################################################################################
# in: portlist string: port1,port2-port3,port4... [, bool: don't pack]
# pack means combine ports in a way suitable for dense -m multiport
# out: undef if empty or error
#   [ 'port1', 'port2' ... ] if not packed
#   [ 'port1,port2,...', 'portN,portN+1...' ... ] if packed
sub parse_portlist
{
  my $s = $_[0];
  my $packit = $_[1] // 1;

  $s =~ s/\s+//g;

  my @pl = split( ',', $s );

  if ( $#pl == -1 )
  {
    print "\n\n??? WARNING: parse_portlist(): got empty list. There is high probability that this is an error in config\n";
    return undef;
  }

  my $o = []; # for output

  my $count = 0; # used for packing

  for my $p ( @pl ) # sanity check and packing for -m multiport
  {
    if ( $p eq '+' || $p eq '-' || $p eq '*'  ) # global stuff comes separate
    {
      push @$o, $p;
      $count = 0;
    }

    elsif ( $p =~ /^(\d+([-:]\d+)?|[a-z]\w+)$/ ) # port1[-:]portN or named port
    {
      my $places = defined( $2 ) ? 2 : 1;
      $p =~ s/-/:/g;

      if ( ( ! $packit ) || ( $count == 0 ) || ( $count + $places > 15 ) ) # push new
      {
        push @$o, $p;
        $count = 0; # it'll add up later
      }

      else # packing: appending to the last element
      {
        $o->[-1] .= ',' . $p;
      }

      $count += $places;
    }

    else
    {
      croak "!!! got invalid port definition from $_[0]";
    }
  }

  $debug and print "\n!DBG: parse_portlist(): in: $s\n!DBG:\tparsed: <", join('> <', @$o ), ">\n";

  return $o;
}

##########################################################################################
#in: existing tree or undef, addr:proto:portlist;... list as a string
#out: {tree} ref: {addr}->{proto}->[ports]
sub parse_app_list
{
  my $tree = $_[0] // {};
  my @args = split( ';', $_[1] );

  for my $app ( @args )
  {
    $app =~ /^([^:]*)(:([^:]*)(:(.*))?)?/; # addr:proto:portlist
    my $addr  = $1 // '*';
    my $protolist = $3 // '*';
    my $ports = defined($5) ? parse_portlist( $5, 0 ) : [ '*' ]; # don't pack so we can sort them out

    exists( $tree->{ $addr } ) or $tree->{ $addr } = {};

    if ( ( $protolist eq '*' or $protolist eq 'all' or $protolist eq 'any' ) # wildcard
         and $ports->[ 0 ] ne '*' )
    {
      $protolist = 'tcp,udp';
    }

    for my $proto ( split( ',', $protolist ) )
    {
      if ( ! exists( $tree->{ $addr }->{ $proto } ) ) # easy way
      {
        $tree->{ $addr }->{ $proto } = $ports;
        next;
      }

      my $existing = $tree->{ $addr }->{ $proto }; # shorcut to existing ports

      my $last = $#$existing; # to save cycles

      for my $pi ( 0..$last )
      {
        for my $ep ( @$existing )
        {
          next if $ep == $ports->[ $pi ];

          push @$existing, $ports->[ $pi ];

          last;
        }
      } # for @$ports
    } # for protolist
  } # for $app

  return $tree;
}

##########################################################################################
# builds a full list of access rules for a given class. replaces config records with pre-cached data
# compiled rules array is [ undef, %hashref ] instead of original [ 'parent class', 'opt1', ... optN ]
# hash contain globals as 'dhcp' => 1 and port-related as 'tcp'=>{someport=>1...} etc
# parms: access record name
# returns: access list hash ref
sub get_class_access_rules
{
  my $class = $_[0];

  exists( $classes{ $class } ) or croak "!!! Undefined class: '$class'";

  my $parent = $classes{ $class }->[0];

  defined( $parent ) or return $classes{ $class }->[1]; # already pre-compiled

  print "Compiling class rules for ", ( $parent ne '' ? "'$parent'::" : 'root class ' ), "'$class'\n      ";

  croak "parent '$parent' of class '$class' does not exists!" if ( $parent ne '' && ! exists $classes{ $parent } );

  my $rules = ( $parent eq '' ) ? {} : dclone( get_class_access_rules( $parent ) ); # pre-compile ancestry list if needed

  my @config_rules = @{ $classes{ $class } };
  shift @config_rules; # get rid of parent class name

  # --- Init tree ---
  for my $proto ( qw~icmp tcp udp~ ) # create protocol lists if needed
  {
    exists $rules->{ $proto } or $rules->{ $proto } = {};
  }
  # --- Init tree end ---

  foreach my $r ( @config_rules ) # getting parent's and own merged
  {
    print "  <$r>";

    # easy add ones without parameters:
    if ( grep( /^$r$/, ( 'boot', 'dhcp', 'drop bad tcp', 'limit scans', 'log bad tcp', 'rtsp', 'quarantine' )) )
    {
      $rules->{ $r } = 1;
      next;
    }

    if ( $r =~ /^logdrop:?(.*)$/ )
    {
      my $p = parse_portlist( $1 ne '' ? $1 : '0:1023' );

      defined( $p ) or croak "Invalid portlist for logdrop: '$r'\n";

      $rules->{ 'logdrop' } = $p;
      next;
    }

    if ( $r eq 'norestrict' ) # blank out all specific ports from parent list
    {
      for my $er ( keys %{ $rules } )
      {
        if ( $er =~ /^(icmp|tcp|udp):/ )
        {
          $er = '';
        }
      }

      $rules->{ $r } = 1;

      # what's also implied
      $rules->{ 'boot' }  = 1;
      $rules->{ 'dhcp' }  = 1;
      $rules->{ 'i-net' } = 'b';

      next;
    }

    if ( $r =~ /^(all|any|bcast|icmp|tcp|udp):(.+)/ ) # portlist follows the colon.
    {
      my $protocols = $1;
      my $portlist = parse_portlist( $2, 0 );

      if ( $protocols eq 'all' || $protocols eq 'any' )
      {
        $protocols = 'tcp,udp';
      }

      $debug and print "\n!DBG: config: $r\n!DBG:\tparsed: $protocols : <", join('> <', @$portlist ), ">\n";

      for my $proto ( split( /,/, $protocols ) )
      {
        for my $port ( @$portlist ) # we need non-packed list here
        {
          if ( $port eq '+' || $port eq '*' || $port eq '-' ) # get rid of any of parent's specifics
          {
            $rules->{ $proto } = { };
          }
          else # specific port name or number
          {
            delete $rules->{ $proto }->{ '+' };
            delete $rules->{ $proto }->{ '-' };
            delete $rules->{ $proto }->{ '*' };
          }

          $rules->{ $proto }->{ $port } = 1; # note for ICMP $port is type
        } # for $port
      } # for $proto

      next;
    } # if ( $r =~ /^(all|any|bcast|icmp|tcp|udp):(.+)/ ) # portlist follows the colon.

    # internet: options: c - clients can, i - interface can. default is both can
    if ( $r =~ /^i-?net(:[cib])?/ )
    {
      $rules->{ 'i-net' } = defined( $1 ) ? $1 : 'b';
      next;
    }

    # allow/deny outgoing traffic from this interface. Used for quarantined virtuals
    if ( $r =~ /^(allowto|denyto):(.+)?/ )
    {
      $rules->{ $1 } = parse_app_list( $rules->{ $1 } // undef, $2 );
      next;
    }

    next if $r eq ''; # maybe a product of some replacements

    croak "!!! unknown access rule: '$r' !!!";
  } # foreach my $r ( @config_rules ) # getting parent's and own merged

  print "\n";

  $classes{ $class } = [ undef, $rules ];

  return $rules;
} # sub get_class_access_rules

###############################################################################
# in: interface ref, rules ref, address, chain name, specify source, is output chain
# parses clauses like 'tcp:23,ssh' and adds rules
sub add_proto_ports_rules
{
  my ( $if, $rules, $addr, $chain, $opts ) = @_;

  $opts = make_complete_set( $opts, { 'dedicated chain' => 0, 'is output' => 0, 'external' => 0 } );

  my $src = ''; # for a host chain we skip using -s addr

  if ( $addr ne '' && ! $opts->{ 'dedicated chain' } ) # non-dedicated chain: always need to specify address
  {
    $src = '-s ' . $addr;
  }

  my $chain_drop = $if->{ 'droplog chains' }->{ $opts->{ 'is output' } ? 'out' : 'in' };

  for my $config_proto ( qw~bcast icmp tcp udp~ )
  {
    my @port_list = ([]); # pack together to optimize via -m multiport

    my $real_proto;

    if ( $config_proto ne 'bcast' )
    {
      $real_proto = $config_proto;
    }
    else
    {
      $real_proto = 'udp';
    }

    my $mp_count = 0; # for packing

    for my $port ( keys %{ $rules->{ $config_proto } } )
    {
      if ( $mp_count == 15 ) # 16 max per multiport
      {
        push @port_list, []; #add new set
        $mp_count = 0;
      }

      push @{ $port_list[ -1 ] }, $port; # another port in this set
      $mp_count += ( $port =~ /:/ ? 3 : 1 );
    }

    next if ( $#port_list == 0 && $#{ $port_list[0] } == -1 ); # no specifics for this protocol

    for my $port_set ( @port_list )
    {
      my @dst_ips;

      if ( $config_proto eq 'bcast' )
      {
        @dst_ips = ( '224.0.0.0/4', # 224.0.0.0 ~ 239.255.255.255 reserved for multicast addresses. RFC 3171
                     '240.0.0.0/4', # reserved (former Class E network) RFC 1700
                     #'255.255.255.255', # is the limited broadcast address (limited to all other nodes on the LAN) RFC 919
                   );
      }

      elsif( exists $opts->{ 'index' } ) # ruleset w defaults for a network - use specified destination ip
      {
        @dst_ips = ( $if->{ 'ip4 addr' }->[ $opts->{ 'index' } ] );
      }

      else # dedicated host chain case - listing all interface ips
      {
        @dst_ips = ( @{ $if->{ 'ip4 addr' } } );
      }

      # for each of interface address
      for my $ipno ( 0..$#dst_ips )
      {
        my $dst = $dst_ips[ $ipno ];
        my $from_to;

        if ( $opts->{ 'external' } )
        {
          $from_to = $src . ' -d ' . $dst;
        }
        else # interface output
        {
          $from_to = $src;
        }

        # no restrictions on i-face + forwarding.
        if ( $port_set->[0] eq '+' )
        {
          addto( $chain, $from_to, '-p', $real_proto, '-j ACCEPT' );
          addto( 'FORWARD', '-i', $if->{ 'if name' }, '-s', $addr, '-p', $real_proto, '-j ACCEPT' );
        }

        elsif ( $port_set->[0] eq '*' ) # in: relaxed access to our iface. out: net scope only
        {
          addto( $chain, $from_to, '-p', $real_proto, '-j ACCEPT' );
        }

        elsif ( $port_set->[0] eq '-' ) # drop him!
        {
          if ( exists( $rules->{ 'logdrop' } ) )
          {
            if ( $real_proto eq 'icmp' )
            {
              addto( $chain, $from_to, '-p icmp -j', $chain_drop );
            }
            else
            {
              dup_rule( [ $rules->{ 'logdrop' } ], $chain, $from_to, '-p', $real_proto, '-m multiport --dports %1', '-j', $chain_drop );
            }
          }

          addto( $chain, $from_to, '-p', $real_proto, '-j DROP' );
        }

        else # very specific ports/icmp types
        {
           my $port = $#{ $port_set } == 0 ? '--dport ' . $port_set->[0] : '-m multiport --dports ' . join( ',', @$port_set );

           if ( $real_proto eq 'icmp' )
           {
             addto( $chain, $from_to, '-p icmp --icmp-type', $port, '-j ACCEPT' );
           }
           else
           {
             addto( $chain, $from_to, '-p', $real_proto, $port, '-j ACCEPT' );
           }
        }
      } # for my $ipno
    } # for my $port_set
  } # for $config_proto
} # sub add_proto_ports_rules

###############################################################################
# construct actual filetering rules. used as for defaults and as a per host config
# parms: if hashref, rules hash ref, address to make for, base chain name
# opts href: { 'dedicated chain' => bool - no need in -s addr, 'is output' => bool - output chain, 'external' => bool - rules for client on the net }
# return: none
sub add_ruleset
{
  my ( $if, $rules, $chain, $addr, $opts ) = @_;
  $opts = make_complete_set( $opts, { 'dedicated chain' => 0, 'is output' => 0, 'external' => 0 } );

  my $src = ''; # for a host chain we skip using -s addr

  my $droplog_chain = $if->{ 'droplog chains' }->{ $opts->{ 'is output' } ? 'out' :'in' };
  my $table_default = $tables{ $current_table }->{ 'defaults' }->{ $opts->{ 'is output' } ? 'OUTPUT' : 'INPUT' };


  if ( $addr ne '' && ! $opts->{ 'dedicated chain' } ) # non-dedicated chain: always need to specify address
  {
    $src = '-s ' . $addr;
  }

  #print "\n + adding ruleset for address '$addr', if: ", $if->{'alias'}, ", dest chain: $chain\n";
  #print '     rule keys: ', join(', ', keys %{$rules}), "\n";

  if ( $opts->{ 'external' } ) # external network hosts
  {
    # boot/dhcp is w/o IP yet. so be it first!
    my $noip = ''; # will be portlist

    if ( exists $rules->{ 'boot' } || exists $rules->{ 'dhcp' } )
    {
      $noip ne '' and $noip .= ',';
      $noip .= 'bootps,bootpc';
    }

    if ( exists $rules->{ 'dhcp' } )
    {
      $noip ne '' and $noip .= ',';
      $noip .= 'dhcp-failover,dhcp-failover2,dhcpv6-client';
    }

    if ( $noip ne '' )
    {
      for my $proto ( qw~tcp udp~ ) # let it be relaxed about tcp/udp specifics for now
      {
        addto( $chain, '-d 255.255.255.255 -p', $proto, '-m conntrack --ctstate NEW -m multiport --dports', $noip, '-j ACCEPT' );
        addto( $chain, '-s 169.254.0.0/16 -p', $proto, '-m conntrack --ctstate NEW -m multiport --dports', $noip, '-j ACCEPT' );
      }
    }

    # look monstrous huh? adding IP check for a host chain
    if ( exists( $if->{ 'access' } ) && exists( $if->{ 'access' }->{ 'hosts' } ) && exists( $if->{ 'access' }->{ 'hosts' }->{ $addr } ) )
    {
      addto ( $chain, '! -s', $addr, '-j', $if->{ 'alias' } . $tables{ $current_table }->{ 'common chains' }->{ 'mismatched ip' } );
    }
  } # if ( $opt->{ 'external' } )

  ################ global rules:

  if ( exists $rules->{ 'i-net' } and $default_if )
  {
    $addr eq '' and croak "chain $chain: 'i-net' needs an address!";

    my $mode = $rules->{ 'i-net' }; # (c)lient/(s)erver/(b)oth

    #if ( $inet and $default_if == $inet ) # if we're not directly connected to inet then NAT will provided somewhere else
    #{
      addto( 'nat:POSTROUTING', '-o', $default_if->{ 'if name' }, '-s', $addr, '-j SNAT --to-source', $default_if->{ 'ip4 addr' }->[0] );
    #}

    if ( ! exists $rules->{ 'norestrict' } ) # don't duplicate
    {
      addto( $chain, $src, '-o', $default_if->{ 'if name' }, '-j ACCEPT' );

      if ( $default_if and $default_if != $if ) # in case of missing/disabled inet if
      {
        addto( 'FORWARD', '-i', $if->{ 'if name' }, '-s', $addr, '-o', $default_if->{ 'if name' }, '-j ACCEPT' );
      }
    }
  } # i-net

  if ( exists $rules->{ 'norestrict' } )
  {
    addto( $chain, '-o', $if->{ 'if name' }, '-s', $addr, '-m conntrack --ctstate NEW -j ACCEPT' );
    addto( $chain, $src, '-j ACCEPT' );
    addto( 'FORWARD', '-i', $if->{ 'if name' }, '-s', $addr, '-j ACCEPT' );
    return; # nothing more to do ;)
  }

  if ( exists $rules->{ 'rtsp' } )
  {
  }

  add_proto_ports_rules( $if, $rules, $addr, $chain, $opts );

  if ( ! $opts->{ 'external' } ) #interface's own
  {
    if ( $opts->{ 'is output' } )
    {
      if ( exists $rules->{ 'quarantine' } ) # before quarantine allow inside trafiic
      {
        for my $n1 ( 0..$#{ $if->{ 'ip4 net' } } ) # for each of interface nets: allowing traffic inbetween first
        {
          addto( $chain, '-s', $if->{ 'ip4 net' }->[$n1], '-d', $if->{ 'ip4 net' }->[$n1], '-j ACCEPT' ); # same net

          my $n2 = $n1 + 1;
          while( $n2 <= $#{ $if->{ 'ip4 net' } } )
          {
            addto( $chain, '-s', $if->{ 'ip4 net' }->[$n1], '-d', $if->{ 'ip4 net' }->[$n2], '-j ACCEPT' ); # same net
            addto( $chain, '-s', $if->{ 'ip4 net' }->[$n2], '-d', $if->{ 'ip4 net' }->[$n1], '-j ACCEPT' ); # same net
            ++$n2;
          }
        }
      } # if quarantine
    } # if output

    else # input to if
    {
    } # input to if

    if ( exists $rules->{ 'allowto' } )
    {
      dup_app_rules( $rules->{ 'allowto' }, $if->{ 'chains' }->{ 'out' }, '-d %1 -p %2 --dport %3 -j ACCEPT' );
    }
  } # if ! external

  if ( exists $rules->{ 'logdrop' } ) # this should be the last
  {
    dup_rule( [ $rules->{ 'logdrop' } ], $chain, $src, '-p tcp -m multiport --dports %1', '-j', $if->{ 'droplog chains' }->{ $opts->{ 'is output' } ? 'out' : 'in' } );
    dup_rule( [ $rules->{ 'logdrop' } ], $chain, $src, '-p udp -m multiport --dports %1', '-j', $if->{ 'droplog chains' }->{ $opts->{ 'is output' } ? 'out' : 'in' } );
  }

  if ( ! $opts->{ 'external' } ) # interface's own OUTPUT rules:
  {
    if ( $opts->{ 'is output' } )
    {
      if ( exists $rules->{ 'quarantine' } ) # block all other output from this interface's ip
      {
        if ( exists $rules->{ 'i-net' } ) # locking out local nets and passing all other through.
        {
          for my $d ( drop_destinations( $if->{ 'alias' } ) )
          {
            addto( $chain, '-d', $d, '-j DROP' );
          }

          addto( $chain, '-j ACCEPT' );
        }
        else # no i-net - dropping all
        {
          addto( $chain, '-s', $addr, '-j DROP' );
        }
      }
      elsif ( exists $rules->{ 'denyto' } ) # or... there are some other restrictions
      {
        dup_app_rules( $rules->{ 'denyto' }, $if->{ 'chains' }->{ 'out' }, '-d %1 -p %2 --dport %3 -j DROP' );
      }
    }
  } # iface own rules

  # this actually breaks semi-trusted host on un-trusted net case, when net is strict, but table's default is ACCEPT for any reason
  # enforce the default mode: this should be the last
  #addto( $chain, $src, '-j', $table_default );

  # nothing should be beyond this point...

} # add_ruleset()

###############################################################################
# parms: interface config hash ref
# return: none
sub add_access_rules
{
  my $if = $_[0];
  my $ifalias = $if->{ 'alias' };
  my $chain_in = $if->{ 'chains' }->{ 'in' };
  my $chain_out = $if->{ 'chains' }->{ 'out' };
  my $acc = $if->{ 'access' }; # at least default should be there

  # making antispoof chain
  my @nets = @{ $if->{ 'ip4 net' } };
  my $chain = $ifalias . '_spoof_check';

  make_chain( $chain_in, $chain );
    addto( $chain_in, '-j', $chain );

    for my $elem ( @nets )
    {
      addto( $chain, '-s', $elem, '-j RETURN' ); # good
    }

    for my $proto ( qw~tcp udp~ ) # DHCP/BOOTP. let it be relaxed about tcp/udp specifics for now
    {
      my $ports='bootps,bootpc,dhcp-failover,dhcp-failover2,dhcpv6-client';
      addto( $chain, '-d 255.255.255.255 -p', $proto, '-m conntrack --ctstate NEW -m multiport --dports', $ports, '-j RETURN' );
      addto( $chain, '-s 169.254.0.0/16 -p', $proto, '-m conntrack --ctstate NEW -m multiport --dports', $ports, '-j RETURN' );
    }
    addto( $chain, '-s 0.0.0.0 -j RETURN' ); # dhcp pre-pass. if it is disabled it will be dropped later

    addto( $chain, '-j', $if->{ 'droplog chains' }->{ 'in' } ); # bad


  my $host_list = defined( $acc->{ 'hosts' } ) ? $acc->{ 'hosts' } : undef;

  #############################
  # for each matched MAC/IP we check ports and finally accepting or denying anythig else.
  # unknowns processed later
  if ( $host_list ) # we have per-host rules there
  {
    #my $mism_mac_chain = $ifalias . $common_chains->{ 'mismatched mac' };
    #make_chain( $chain_in, $mism_mac_chain );
    #  addto( $mism_mac_chain, '-j LOG --log-level info --log-prefix', '"ipt4-' . $ifalias . ' MAC+,IP-" ' );
    #  addto( $mismm_mac_chain, '-j DROP' );

    my $mism_ip_chain = $ifalias . $common_chains->{ 'mismatched ip' };
    make_chain( $chain_in, $mism_ip_chain );
      addto( $mism_ip_chain, '-j LOG --log-level info --log-prefix', '"ipt4-' . $ifalias . ' MAC-,IP+" ' );
      addto( $mism_ip_chain, '-j DROP' );

    # HOSTS:
    # adding individual host's rules. make it diff-friendly sorted
    for my $host ( sort( keys %{ $host_list } ) )
    {
      gethostbyname $host or croak "!!! Host doesn't resolve: '$host' !!!";

      my $rules = get_class_access_rules( $host_list->{ $host }->[1] );
      my $ports_chain = $if->{ 'alias' } . $common_chains->{ 'host prefix' } . $host;

      make_chain( $chain_in, $ports_chain, "Access class: '" . $host_list->{ $host }->[1] . "'" );

      addto( $chain_in, '-m mac --mac-source', $acc->{ 'hosts' }->{ $host }->[0], '-j', $ports_chain );

      add_ruleset( $if, $rules, $ports_chain, $host, { 'dedicated chain' => 1, 'is output' => 0, 'external' => 1 } );
    } # for my $host
  } # if $host_list

  # and defaults
  for my $i ( 0..$#{ $if->{ 'ip4 net' } } ) # for each of interface nets
  {
    defined( $if->{ 'ip4 default class' }->[ $i ] ) or croak "!! Undefined class for network #$i: " . $if->{ 'ip4 net' }->[ $i ];

    put_comment_lines( $chain_in, 'Rules for network: ' . $if->{ 'ip4 net' }->[ $i ] . ", Access class: '" . $if->{ 'ip4 default class' }->[ $i ] . "'" );

    my $r = get_class_access_rules( $if->{ 'ip4 default class' }->[ $i ] );

    if ( exists( $r->{ 'drop bad tcp' } ) || exists( $r->{ 'log bad tcp' } ) )
    {
      my $log = exists( $r->{ 'log bad tcp' } );
      my $chain = $ifalias . '_' . ( $log ? 'log' : 'drop' ) . 'badtcp';

      if ( ! exists( $if->{ 'chains' }->{ $chain } ) )
      {
        make_chain( $chain_in, $chain );
        $if->{ 'chains' }->{ $chain } = 1;
      }

      make_bad_tcp_rules( $chain_in, $chain, $log );

      addto( $chain_in, '-s', $if->{ 'ip4 net' }->[ $i ], '-p tcp -j', $chain );
    } # malformed tcp

    if ( exists( $r->{ 'limit scans' } ) )
    {
      my $chain = $ifalias . '_limscans';

      if ( ! exists( $if->{ 'chains' }->{ 'limit scans' } ) )
      {
        make_chain( $chain_in, $chain );
        $if->{ 'chains' }->{ 'limit scans' } = $chain;
      }

      addto( $chain, '-p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/m -j RETURN' );
      addto( $chain, '-p icmp --icmp-type  8 -m limit --limit 10/m -j ACCEPT' );
      addto( $chain, '-p icmp --icmp-type 11 -m limit --limit 10/m -j ACCEPT' );
      log_it( $chain, '', 'DROP', '' );

      addto( $chain_in, '-j', $chain );
    } # limit scans

    add_ruleset( $if, $r, $chain_in, $if->{ 'ip4 net' }->[ $i ], { 'index' => $i, 'dedicated chain' => 0, 'is output' => 0, 'external' => 1 } );

    # interface's own rules:
    if ( $if->{ 'chains' }->{ 'out' } ne '' ) # out chain name set, so rules must be applied
    {
      my $ch = $if->{ 'chains' }->{ 'out' };

      put_comment_lines( $ch, 'Rules for interface: ' . $if->{ 'ip4 addr' }->[ $i ] . ", Access class: '" . $if->{ 'ip4 interface class' }->[ $i ] . "'" );

      $r = get_class_access_rules( $if->{ 'ip4 interface class' }->[ $i ] );

      add_ruleset( $if, $r, $ch, $if->{ 'ip4 addr' }->[ $i ], { 'index' => $i, 'dedicated chain' => 1, 'is output' => 1, 'external' => 0 } );
    }
  } # for my $i ( 0..$#{ $if->{ 'ip4 net' } } ) # for each of interface nets
} # sub add_access_rules()

##########################################################################################
sub table_start
{
  $current_table = $_[0];

  exists $tables{ $current_table } or croak "!!! table_start for unknown '$current_table'!!!";

  $common_chains = $tables{ $current_table }->{ 'common chains' };

  print $out_file "\n\n\n", '#' x 55, "\n##################### Table: $current_table ######################\n", '#'x55, "\n\n\n";

  print $out_file "\n*$current_table\n";

  while ( my ($c,$p) = each %{ $tables{ $current_table }->{ 'defaults' } } )
  {
    print $out_file ":$c $p [0:0]\n";
  }
}

##########################################################################################
# recursively flushes chain's subtree and then itself
# parms: chain name
sub chain_flush
{
  my $chain_name = $_[0];
  exists $chains{ $chain_name } or return;

  my $chain = $chains{ $chain_name };
  my $rules = shift @{ $chain };

  for my $sub_chain ( @{ $chain } )
  {
    chain_flush( $sub_chain );
  }

  print $out_file "\n";
  for my $line ( @{ $rules } )
  {
    print $out_file $line, "\n";
  }

  delete $chains{ $chain_name };
}

##########################################################################################
# flushes current table to outfile
sub table_flush
{
  my ($chain, $table_name, $chain_name);

  # making defaults as rules to be visible to stats
  #while ( my ($c,$p) = each %{ $tables{ $current_table }->{ 'defaults' } } )
  #{
  #  addto($c, '-j', $p);
  #}

  # flushing standard chains trees
  for $chain ( keys %{ $tables{ $current_table }->{ 'defaults' }} )
  {
    print $out_file "\n\n", '#'x30, "\n";
    chain_flush( $current_table . ':' . $chain );
  }

  my $errors = 0;
  for $chain ( keys %chains ) # checking for stale names
  {
    next if $chain !~ /^$current_table:/;
    ++$errors;
    print "!!! Uncalled chain found: '$chain'\n";
  }

  exit if $errors;

  print $out_file "\nCOMMIT\n\n\n";
}

##########################################################################################
# args: chain, optional message
sub put_comment
{
  check_args('put_comment', @_);
  my ($barechain, $chain) = qualify_chain_name( shift @_ );

  exists $chains{ $chain } or croak "Attempt to comment into chain '$chain' - " . join(' ', @_);

  my $cmt = @_ ? '# ' . join(' ', @_) : '';

  push @{ $chains{ $chain }->[0] }, $cmt;
}

##########################################################################################
# in: chain, _lines_ array to put out
sub put_comment_lines
{
  my ($barechain, $chain) = qualify_chain_name( shift @_ );

  exists $chains{ $chain } or croak "Attempt to comment into chain '$chain' - " . join(' ', @_);

  for my $cmt_in ( @_ )
  {
    my $c = $cmt_in;

    if ( $c !~ /^\s*$/ )
    {
       $c = '# ' . $c;
    }

    push @{ $chains{ $chain }->[0] }, $c;
  }
}

##########################################################################################
# in: owner_chain, log_suffix, action, rule to divert
sub log_it
{
  my ( $owner, $suffix, $action, @rule ) = @_;
  my $chain = $owner . '_log_' . $suffix;

  my ( undef, $chain_q ) = qualify_chain_name( $chain );
  if ( ! exists $chains{ $chain_q } ) # making new chain
  {
    make_chain( $owner, $chain );

    addto( $chain, '-j LOG --log-level info --log-prefix "ipt4-' . $suffix . ': "' );
    addto( $chain, '-j', $action );
  }

  addto( $owner, join(' ', @rule), '-j', $chain );
}

##########################################################################################
# in: if alias or predefined chain name[, what kind of chains to create]
#     kind can be b=both(default), d=drop only and o=OK only
sub make_log_chains
{
  my ( $name, $kind ) = @_;
  defined( $kind ) or $kind = 'b';

  my ( $parents, $prefix );

  my $if = exists $net_interfaces{ $name } ? $net_interfaces{ $name } : undef;

  if ( $if )
  {
    $parents = $if->{ 'chains' };
    # set empty names as default
    $if->{ 'droplog chains' } = { 'in' => '', 'out' => '' };
    $if->{ 'oklog chains' }   = { 'in' => '', 'out' => '' };
  }
  else
  {
    $parents = { 'in' => $name, 'out' => '' };
  }

  foreach my $io ( qw( in out ) )
  {
    my $parent = $parents->{ $io };

#print " . make log chains(): io: $io, parent: '$parent'\n";
    next if ( $parent eq '' );

    $prefix = $parent;# . '_' . $name;
    my $drop = "${prefix}_log_drop";
    my $ok   = "${prefix}_ok_log";

#print "\t\tdrop: '$drop', ok: '$ok'\n";
    if ( $if )
    {
      $if->{ 'droplog chains' }->{ $io } = $drop;
      $if->{ 'oklog chains' }->{ $io } = $ok;
    }

    if ( $kind ne 'o' )
    {
      make_chain( $parent, $drop );
        #addto( $drop, '-p icmp --icmp-type 3 -j DROP' ); #  unreachables
        addto( $drop, '-j LOG --log-level info --log-prefix', qq~"ipt4-${prefix}-DENY "~ );
        addto( $drop, '-j DROP' );
    }

    if ( $kind ne 'd' )
    {
      make_chain( $parent, $ok );
        addto( $ok, '-j LOG --log-level info --log-prefix', qq~"ipt4-${prefix}-OK "~ );
        addto( $ok, '-j ACCEPT' );
    }
  }  # for my $io ( in out )
}

##########################################################################################
# in: 'chain', 's'|'d', host[:port], args
sub add_hostport_to
{
  my $chain = shift @_;
  my $dst = shift(@_);
  $dst =~ s/^-*/-/;
  my ($h, $p) = split /:/, shift(@_);

  $h = $h eq '*' ? '' : $dst . ' ' . $h;
  defined($p) and $p = '--dport ' . $p;

  $a = join ' ', @_;

  if ( ! defined($p) )
  {
    addto( $chain, $h, $a );
    return;
  }

  addto( $chain, $h, '-p tcp', $p, $a );
  addto( $chain, $h, '-p udp', $p, $a );
}

##########################################################################################
# in: 'chain name', args
sub addto
{
  check_args('addto', @_);
  my ($barechain, $chain) = qualify_chain_name( shift @_ );

  exists $chains{ $chain } or croak "Non-existent chain '$chain', adding: '" . join(' ', @_) . "'";

  @_ or croak "invalid call to addto() with: '$chain'";

  my $r = join(' ', @_);
  $r =~ s/\s\s+/ /g; # compact it
  $r =~ s/^\s*/ /g;

  if ( $r =~ /\s+-j\s+(\S+)/ ) # check for jump rule names correct
  {
    my $jc = $1;
    if ( ! grep( $jc, qw~ACCEPT DROP RETURN~ ) ) # flip on non-std targets
    {
      exists $chains{ $1 } or carp "Non-existent target '$jc' for -j, adding: '" . join(' ', @_) . "'";
    }
  }

  # automagically add conntrack
#  if ( $current_table eq 'filter' && $r !~ /conntrack/ &&
#       (    ( $chain eq 'filter:INPUT'  && $r !~ /\b-o \w+/ ) # except potential forwarding in or out
#         || ( $chain eq 'filter:OUTPUT' && $r !~ /\b-i \w+/ )
#       )
#  )
#  {
#    $r =~ s/-j ACCEPT/-m conntrack --ctstate NEW -j ACCEPT/;
#  }

  push @{ $chains{ $chain }->[0] }, '  -A ' . $barechain . $r;
}

##########################################################################################
# in: 'chain parent', 'chain name', optional comments
sub make_chain
{
  my (undef, $parent) = qualify_chain_name( shift @_ );
  my ($barechain, $chain) = qualify_chain_name( shift @_ );
  exists $chains{ $chain } and croak "Attempt to re-create chain '$chain'";
  exists $chains{ $parent } or croak "No parent '$parent' for new chain '$chain'";

  $chains{ $chain } = [ [] ]; # own rules
  push @{ $chains{ $parent } }, $chain; # add to sub-tree

  if ( @_ )
  {
    put_comment_lines( $barechain, '', '-'x30, @_, '-'x30);
  }
  #else
  #{
  #  put_comment_lines( $barechain, '', '-'x10);
  #}

  push @{ $chains{ $chain }->[ 0 ] }, '-N ' . $barechain;
}

##########################################################################################
# in: full or bare name
# out: array( bare, full )
sub qualify_chain_name
{
  my $s = $_[0];
  defined($s) or croak "!!! undef as chain name? !!!";
  my @n = ( $s, $s );
  $n[0] =~ s/^.+://;
  $n[1] =~ /:/ or $n[1] = $current_table . ':' . $n[1];
  #print STDERR "q> '$n[0]' / '$n[1]'\n";
  return @n;
}

##########################################################################################
# produce list of nets to drop outgoing to, filtering the ones that is allowed
# in: 'interface name', optional additional exclude list
sub drop_destinations
{
  @_ or return @cross_drop_list;

  my @nets;

  my $ifalias = shift @_;
  my $if = $net_interfaces{ $ifalias };

  for my $drop_net ( @cross_drop_list )
  {
    my $dropit = 1;

    for my $net ( @{ $if->{ 'ip4 net' } } )
    {
      $dropit = 0 if $drop_net eq $net;
    }

    for my $excl ( @_ )
    {
      $dropit = 0 if $drop_net eq $excl;
    }

    $dropit and push @nets, $drop_net;
  }

  return @nets;
}

##########################################################################################
# initialization of necessary parameters
sub init
{
  scan_if(); # get interfaces configuration

  %chains = (
    'filter:INPUT'   => [[]],
    'filter:OUTPUT'  => [[]],
    'filter:FORWARD' => [[]],
    'nat:INPUT'   => [[]],
    'nat:OUTPUT'  => [[]],
    'nat:PREROUTING' => [[]],
    'nat:POSTROUTING' => [[]],
  );
}

###############################################################################
# Fills missing keys from original hashref with ones from secondary: default
# in: original hashref or undef, hashref of defaults, check original keys
# out: hashref of complete set
sub make_complete_set
{
  my ( $orig, $def, $check ) = @_;

  defined( $orig ) or return { %$def }; # make new hashref

  if ( $check ) # sanity check for original to not have keys that not in defaults
  {
    for my $k ( keys %$orig )
    {
      exists( $def->{ $k } ) or croak "defaults has no key '$k'. check your config or hash \$interface_default_options";
    }
  }

  for my $k ( keys %$def )
  {
    next if exists $orig->{ $k };

    $orig->{ $k } = $def->{ $k };
  }

  return $orig;
}

##########################################################################################
# pure debug service: check for undef args and report it verbosely
# in: caller name, any original args
sub check_args
{
  my $func = shift(@_);
  my $s = '';
  my $errs = 0;
  my $warns = 0;

  for my $a ( 0..$#_ )
  {
    if ( ! defined($_[$a]) )
    {
      carp "!!! check_args: undefined arg #$a\n";
      $s .= '> <!!!UNDEF!!!';
      ++$errs;
      ++$errors_count;
    }
    elsif ( $_[$a] eq '' )
    {
      #carp "    check_args: empty string arg #$a\n";
      $s .= '> <!EMPTY!';
      ++$warns;
      ++$warnings_count;
    }
    else
    {
      $s .= ($s eq '' ? '<' : '> <' ) . $_[$a];
    }
  }

  if ( $errs )#|| $warns )
  {
    carp "\tErrs: $errs, warns: $warns\n\t$func( $s> )\n";
  }
}

##########################################################################################
# scans interfaces. checks config sanity
# returns none
sub scan_if
{
  open I, '/sbin/ip a | ' or croak "ip a: $!";

  my ( $if, $if_real_name, $if_attr, $type, $mac, $addr, $mask, $bcast, $net );

  while(<I>)
  {
    if ( /^\d+:\s+([^:]+):\s+(.+)/ ) # interface name
    {
      #1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      #3: enp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000

      $if_real_name = $1;
      $if_attr = $2;

      next;
    }

    next if $if_real_name eq 'lo' ; # no interest in this

    if ( /^\s+link\/(\S+)\s+(\S+)/ ) # MAC
    {
      #link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      #link/ether bc:5f:f4:53:d9:6b brd ff:ff:ff:ff:ff:ff

      my $type = $1;
      my $mac = lc($2);

      $if = undef; # to check if this interface is registered in config

      next if $type eq 'loopback' ; # no interest in this

      # substituting %net_interfaces logical name subarray
      for my $ni ( keys %net_interfaces )
      {
        if ( ( $net_interfaces{ $ni }->{ 'mac' } eq '' && lc( $ni ) ne lc( $if_real_name ) ) # virtual? go by name
          || ( $net_interfaces{ $ni }->{ 'mac' } ne '' && $mac ne lc( $net_interfaces{ $ni }->{ 'mac' } ) ) ) # MAC no match either
        {
          next;
        }

        $if = $net_interfaces{ $ni }; #gotcha
        print "+ $ni -> $if_real_name\n";

        $if->{ 'alias' } = $ni; # for reverse ref
        $if->{ 'if type' } = $type;
        $if->{ 'if name' } = $if_real_name;
        $if->{ 'attr' } = $if_attr;
        $if->{ 'up' } = ( $if_attr =~ /\b(UP)\b/ ) ? 1 : 0;
        $if->{ 'default' } = 0;
        last;
      }

    }

    if ( /^\s+inet\s+([\d.]+)\/(\d+)\s+(brd|scope)\s+(\S+)/ ) # IPv4
    {
      #inet 127.0.0.1/8 scope host lo
      #inet 10.1.1.1/24 brd 10.1.1.255 scope global enp2s0

      $addr = $1;
      $mask = int($2);
      $bcast = $3 eq 'brd' ? $4 : `/bin/ipcalc -b $1/$2`;

      $net = `/bin/ipcalc -n $1/$2`;
      chomp $net;
      $net =~ s/^\D+//;
      $net = "$net/$mask";

      chomp $bcast;
      $bcast =~ s/^\D+//; # remove BROADCAST=

      if ( ! defined( $if ) )
      {
        print "\n??? There is no configured interface with IP4 assigned: $if_real_name\n\n";
        next;
      }

      my $i = $#{ $if->{ 'ip4 addr' } };

      while( )
      {
        last if $if->{ 'ip4 addr' }->[ $i ] eq $addr;
        --$i < 0 and croak "!!! $if_real_name: $addr not in config !!!";
      }

      $mask  != $if->{ 'ip4 mask'  }->[ $i ] and croak "!!! $if_real_name: $addr mask mismatch: $mask !!!";
      $bcast ne $if->{ 'ip4 bcast' }->[ $i ] and croak "!!! $if_real_name: $addr bcast mismatch: computed: '$bcast' !!!";
      $net   ne $if->{ 'ip4 net'   }->[ $i ] and croak "!!! $if_real_name: $addr net mismatch: computed: '$net' !!!";

      next;
    }

    next if ! defined( $if );

    #if ( /^\s+inet6\s+(\S+)\/(\D+)(brd|scope)\s+(\S+)/ ) # IPv6
    #{
      #inet6 ::1/128 scope host
    #}
  } # while<I>

  close I;

  # now checking if there are unavailable interfaces in our config
  my $missed = 0;
  for my $ni ( keys %net_interfaces )
  {
    next if exists( $net_interfaces{ $ni }->{ 'alias' } );

    if ( $net_interfaces{ $ni }->{ 'options' }->{ 'volatile' } )
    {
      print "!!! Volatile interface is not active now: $ni\n";
      # filling by the heart then
      $if = $net_interfaces{ $ni };
      $if->{ 'alias' } = $ni; # for reverse ref
      $if->{ 'if type' } = 'virtual';
      $if->{ 'if name' } = $ni;
      $if->{ 'attr' } = '';
      $if->{ 'up' } = 0;
      $if->{ 'default' } = 0;
    }
    else
    {
      ++$missed;
      print "!!! No such interface: $ni\n";
    }
  }

  exit(1) if $missed;

  # get routing default
  #default via 192.168.1.1 dev wlp0s29u1u7
  open I, '/sbin/ip ro | ' or croak "ip ro: $!";

  while(<I>)
  {
    next if ! /^default via (\S+) dev (\S+)/;

    my $gw = $1;
    my $dev = $2;

    for my $ni ( keys %net_interfaces )
    {
      next if $dev ne lc( $net_interfaces{ $ni }->{ 'if name' } );

      $net_interfaces{ $ni }->{ 'default' } = 1;
      $net_interfaces{ $ni }->{ 'gw' } = $gw;

      $default_if and croak "another default route found: " . $default_if->{ 'alias' } . ' and ' . $ni;
      $default_if = $net_interfaces{ $ni };
    }
  }

  close I;
}
