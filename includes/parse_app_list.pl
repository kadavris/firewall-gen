# This is a part of firewall-gen utility
# This module holds sub used to parse address:proto:port-list constructions

##########################################################################################
# parses APP (Address/Proto/Port) lists into existing proto->port tree
#in: TAG, existing tree or undef, addr[:proto:portlist]|:proto[:portlist];... list as a string
#out: {tree} ref: {addr}->{proto}->[ports]
sub parse_app_list
{
  my $tag = $_[0];
  my $tree = $_[1] // {};
  my @args = split( /;/, $_[2] );

  for my $app ( @args )
  {
    my @app = split( /:/, $app );

    if ( $#app == -1 || $#app > 2 ) # addr:proto:portlist
    {
      croak "invalid addr[:protocols list[:port list]] clause: $tag";
    }

    my $addr = $app[ 0 ] ne '' ? $app[ 0 ] : '*';
    shift @app;

    my $protolist = '*';

    if ( $#app > 0 ) # there should be proto:ports
    {
      $app[ 0 ] ne '' and $protolist = $app[ 0 ];
      shift @app;
    }

    my $ports = $#app > -1 && $app[ 0 ] ne '' ? parse_portlist( $tag . '/' . $app, $app[ 0 ], 0 ) : [ '*' ]; # don't pack so we can sort them out

    if( $addr ne '*' )
    {
      if ( $addr =~ /^[.:\/\d]+$/ )
      {
        validate_ip4( $addr );
      }
      else
      {
        my ( $name, $aliases, $addrtype, $length, @addrs ) = gethostbyname( $addr );
        $name or croak "!!! Host doesn't resolve: '$addr' at $tag !!!";
        $addr = Socket::inet_ntoa( $addrs[0] );
      }
    }

    $debug and print ". parse_applist( $app ): addr: $addr, proto: $protolist, ports: ", join( ',', @$ports ), "\n";

    exists( $tree->{ $addr } ) or $tree->{ $addr } = {};

    if ( ( $protolist eq '*' or $protolist eq 'all' or $protolist eq 'any' ) # wildcard
         and $ports->[ 0 ] ne '*' )
    {
      $protolist = 'tcp,udp';
    }

    for my $proto ( split( /,/, $protolist ) )
    {
      if ( ! grep( $proto, qw( tcp udp icmp bcast ) ) )
      {
        croak "invalid proto in $tag";
      }

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

1;
