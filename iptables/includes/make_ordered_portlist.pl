# This is a part of firewall-gen utility

###############################################################################
# makes sorted array out of rule portlist, making more specific ports come first
# to allow exceptions from broad rules: like allow ssh, but deny whole 0-1024 range
# in: rules hash, proto name
# out: ( [denied ports if any], [allowed ports if any] )
sub make_ordered_portlist_sortfunc
{
  my @a = split /:/, $_[0];
  my @b = split /:/, $_[1];

  # easy cases:
  my $c = $#a <=> $#b; # single or range?

  $c != 0 and return $c; # one is single and other is range

  if ( $#a == 0 && $#b == 0 ) # single ports - natural order
  {
    return $a[0] <=> $b[0];
  }

  $c = $a[0] <=> $b[0]; # for ranges we sort on lower bound if differ
  $c != 0 and return $c;

  # or upper bound
  return $a[1] <=> $b[1];
}

#------------------------
sub make_ordered_portlist
{
  my ( $r, $proto ) = @_;

  my $proto_num = getprotobyname( $proto );

  my $en = [];
  my $dis = [];
  my @out;


  for my $k ( keys %$r )
  {
    my $num = $k;

    if ( $k !~ /^\d+(:\d+)?$/ ) # non-numeric. resolving
    {
       my ( $s_name, $s_aliases, $num, $s_proto ) = getservbyname( $k, $proto );
       defined( $num ) or croak "$proto:$k does not resolve!";
    }

    if ( $r->{ $k } == 1 )
    {
      push @$en, $num;
    }
    else
    {
      push @$dis, $num;
    }
  }

  return ( [ sort make_ordered_portlist_sortfunc @$dis ], [ sort make_ordered_portlist_sortfunc @$en ] );
}

1;
