# This is a part of firewall-gen utility
# This module is for IP utility functions

##########################################################################################
# in: addr/mask or addr:mask [, optional full address to report]
# out: returned if OK
sub validate_ip4
{
  my $in = $_[0];
  my $is_long_mask = defined( $_[1] );
  my $full = $_[1] // $_[0];
  $in =~ s/^\s+//;
  $in =~ s/\s+$//;

  my $has_long_mask = 0;

  if ( $in =~ /:/ )
  {
    my @a = split /:/, $in;
    $#a > 1 and croak "double mask in IP: $full";

    $in = $a[0];
    validate_ip4( $a[1], $_[0] );
    $has_long_mask = 1;
  }

  my @a = split /[.\/]/, $in;

  if ( $#a < 3 || $#a > ( 4 - $is_long_mask ) # mask with /mask
       || ( $has_long_mask && $#a != 3 ) ) # both mask types are here
  {
    croak "Invalid ip: <$full>";
  }

  my $bcast = 0; # 1 if 255 is found
  my $v;

  for $b ( 0..3 )
  {
    if ( $a[ $b ] =~ /\D/ )
    {
      croak "Non-digit in byte #$b of ip: $full";
    }

    $v = int( $a[ $b ] );

    if ( $v > 255 )
    {
      croak "bad byte #$b of ip: $full";
    }

    $v == 255 and $bcast = 1;
  }

  $#a == 3 and return; # no mask

  $bcast and croak "broadcast with bitmask in $full";

  $v = int( $a[ 4 ] );

  if ( $v == 0 || $v > 32 )
  {
    croak "Invalid bitmask in $full";
  }
}

##########################################################################################
# normalize network ip to net/mask
# in: address
# out [ addr/bitmask, address, bitmask ]
sub normalize_net_addr
{
  my $in = $_[0];
  $in =~ s/^\s+//;
  $in =~ s/\s+$//;

  my $mask = 0;

  if( $in =~ /([^:]+):(.+)/ ) # converting to bits
  {
    $in = $1;
    my @m = split( /\./, $2 );
    my $bits = 8;

    while( 1 )
    {
      last if $m[ 0 ] & 0xf0 == 0;

      if( --$bits == 0 )
      {
        shift @m;
        last if $#m == -1;
        $bits = 8;
      }

      ++$mask;
      $m[ 0 ] <<= 1;
    }

    return ( "$in/$mask", $in, $mask );
  }

  if ( $in =~ /([^\/]+)\/(.+)/ )
  {
    return ( $_[0], $1, int( $2 ) );
  }

  return ( $_[0], $_[0], 32 )
}

##########################################################################################
# provides 1st and last network address in integer for for comparisons
# in: net
# out: [ from, to ]
sub get_net_range
{
  my ( $skip, $addr, $mask ) = normalize_net_addr( $_[0] );

  $mask = int( $mask );
  my $from = 0;
  map( { $from <<= 8; $from += int( $_ ); } split( /\./, $addr )); # making int

  $from = ( $from >> ( 32 - $mask ) ) << ( 32 - $mask ); # clearing host part

  return ( $from, $from + eval( '0b0' . ( 1 x ( 32 - $mask ) ) ) );
}

##########################################################################################
# in addr,net
# out: true if addr is in the provided net
sub is_addr_in_net
{
  validate_ip4( $_[0] );
  validate_ip4( $_[1] );

  my @a1 = get_net_range( $_[0] );
  my @a2 = get_net_range( $_[1] );

  return ( $a1[ 0 ] >= $a2[ 1 ] && $a1[ 1 ] <= $a2[ 1 ] );
}

##########################################################################################
# in: addr to look up
# out: ( if hashref, net ) if found at our interface, undef if not found
sub is_local_address
{
  for my $ifkey ( keys %net_interfaces )
  {
    my $if = $net_interfaces{ $ifkey };
    for my $net ( @{ $if->{ 'ip4 net' } } )
    {
      return ( $if, $net ) if is_addr_in_net( $_[0], $net );
    }
  }

  return undef;
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
      #10259: cni-hassio: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000

      # bridge:
      #10263: veth1de6a280@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master cni-hassio state UP group default 
      #  link/ether 22:57:4f:28:46:0d brd ff:ff:ff:ff:ff:ff link-netns cni-3d415fd2-5e98-4eb0-103f-b98afa3c4a26
      #  inet6 fe80::4464:ecff:fe66:fcef/64 scope link 
      #  valid_lft forever preferred_lft forever
      $if_real_name = $1;
      $if_attr = $2;

      if( $if_attr =~ /\bmaster\s+(\S+)/ ) # adding to main
      {
        my $m = $1;

        if( exists( $net_interfaces{ $m } ) )
        {
          $if_real_name =~ s/\@.+//;

          exists( $net_interfaces{ $m }->{ 'secondary interfaces' } ) or $net_interfaces{ $m }->{ 'secondary interfaces' } = {};

          $net_interfaces{ $m }->{ 'secondary interfaces' }->{ $if_real_name } = $if_attr;

          $verboseness > 0 and print "++ Added secondary interface $if_real_name to main $m\n";

          $if_real_name = undef; #to skip the rest if its config
        }
      }

      next;
    }

    next if ! $if_real_name || $if_real_name eq 'lo' ; # no interest in this

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
        $verboseness > 1 and print "+ $ni -> $if_real_name\n";

        $if->{ 'config name' } = $ni; # for reverse ref
        $if->{ 'if type' } = $type;
        $if->{ 'if name' } = $if_real_name;
        defined( $if->{ 'name' } ) or $if->{ 'name' } = $if_real_name; # to use in chain names, etc
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
    next if exists( $net_interfaces{ $ni }->{ 'if name' } );

    if ( $net_interfaces{ $ni }->{ 'options' }->{ 'volatile' } )
    {
      $verboseness > 0 and print "NOTE: Volatile interface is NOT ACTIVE now: $ni\n";
      # filling by the heart then
      $if = $net_interfaces{ $ni };
      $if->{ 'config name' } = $ni; # for reverse ref
      $if->{ 'if type' } = 'virtual';
      $if->{ 'if name' } = $ni;
      $if->{ 'attr' } = '';
      $if->{ 'up' } = 0;
      $if->{ 'default' } = 0;
    }

    elsif( ! $net_interfaces{ $ni }->{ 'options' }->{ 'enabled' } )
    {
      $verboseness > 0 and print "NOTE: DISABLED interface: $ni\n";
      $if = $net_interfaces{ $ni };
      $if->{ 'config name' } = $ni; # for reverse ref
      $if->{ 'if type' } = 'DISABLED';
      $if->{ 'if name' } = $ni;
      $if->{ 'attr' } = '';
      $if->{ 'up' } = 0;
      $if->{ 'default' } = 0;
    }
    else
    {
      ++$missed;
      print "!!! ERROR: No such interface: $ni\n";
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

      $default_if and croak "another default route found: " . $default_if->{ 'if name' } . ' and ' . $ni;
      $default_if = $net_interfaces{ $ni };
    }
  }

  close I;
}

1;
