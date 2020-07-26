#!/bin/perl
use warnings;

sub update_ipset_list
{
  my $output_list = $_[0];
  my $port = $_[1];

  open IP, "/sbin/ipset list $output_list |";

  while(<IP>)
  {
    next if ! /^(\d+\.\d+\.\d+\.\d+),\D+$port/;

    my $ip = $1;

    if ( defined($hosts{$ip}) )
    {
      $hosts{$ip} = -1;
    }
    else
    {
      print "- Removing $ip\n";
      system qq~/sbin/ipset del $output_list $ip,$port~;
    }
  }

  close IP;

  for $ip (keys %hosts)
  {
    next if $hosts{$ip} < 2;

    print "+ Adding $ip\n";
    system qq~/sbin/ipset add $output_list $ip,$port~;
  }
}

1;
