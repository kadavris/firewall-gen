# This is a part of firewall-gen utility
# This module holds sub used to parse port-list constructions

##########################################################################################
# Used to parse freestyle config portlists coming as a modifier after the statemet:
#   e.g. tcp:ports... logdrop:someports or quarantine:...
# in: TAG, portlist string: port1,port2:port3,port4... [, bool: don't pack]
# pack means combine ports in a way suitable for dense -m multiport
# out: undef if empty or error
#   [ 'port1', 'port2' ... ] if not packed
#   [ 'port1,port2,...', 'portN,portN+1...' ... ] if packed
sub parse_portlist
{
  my $tag = $_[0];
  my $s = $_[1];
  my $packit = $_[2] // 1;

  $s =~ s/\s+//g;

  my @pl = split( /,/, $s );

  #if ( $#pl == -1 )
  #{
  #  print "\n\n??? WARNING: parse_portlist(): got empty list. There is high probability that this is an error in config\n";
  #  return undef;
  #}

  my $o = []; # for output

  my $count = 0; # used for packing

  for my $p ( @pl ) # sanity check and packing for -m multiport
  {
    if ( $p eq '+' || $p eq '-' || $p eq '*'  ) # global stuff comes separate
    {
      $packit and croak "encountered wildcard with 'pack ports' option at $tag, $s";
      push @$o, $p;
      $count = 0;
    }

    elsif ( $p =~ /^(\d+(:\d+)?|[a-z]\w+(-\w+)?)$/ ) # port1[:]portN or named port
    {
      my $places = defined( $2 ) ? 2 : 1;

      if ( $p !~ /^\d+(:\d+)?$/ ) # non-numeric. resolving
      {
         # TODO: supply real proto here somehow
         my ( $s_name, $s_aliases, $num, $s_proto ) = getservbyname( $p, 'tcp' );
         if ( ! defined( $num ) )
         {
           ( $s_name, $s_aliases, $num, $s_proto ) = getservbyname( $p, 'udp' );
           defined( $num ) or croak "port name $p does not resolve in $tag!";
         }

         $p = $num;
      }

      if ( ( ! $packit ) || ( $count == 0 ) || ( $count + $places > 15 ) ) # push new
      {
        push @$o, $p;
        $count = 0; # it'll add up later
      }

      else # packing: appending to the last element
      {
        $o->[ -1 ] .= ',' . $p;
      }

      $count += $places;
    }

    else
    {
      croak "!!! got invalid port definition from $tag, full list: " . $s . ' | element: "' . $p . '"';
    }
  }

  $debug and print "\n!DBG: parse_portlist(): in: $s\n!DBG:\tparsed: <", join('> <', @$o ), ">\n";

  return $o;
}

1;
