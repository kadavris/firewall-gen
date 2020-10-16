
###############################################################################
# in: name of the key in settings. used for multiple inet interfaces
sub inet_rules
{
  my $key_name = $_[0];
  my $if = $net_interfaces{ $key_name };

  $if->{ 'default' } == 1 or croak "inet interface is not the default route!";

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
      my ( $proto, $method ) = split( /:/, $key );

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
          @portlist = split( /,/, $3 );
        }
        else
        {
          $addr = '';
          @portlist = split( /,/, $1 );
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

1;
