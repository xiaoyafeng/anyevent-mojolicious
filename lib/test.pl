#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
# eval "use AnyEvent::Mojolicious::Patcher";
#use AnyEvent::Mojolicious::Patcher;
use AnyEvent::Mojolicious::IOLoop;

#my $loop = AnyEvent::Mojolicious::IOLoop->singleton();

#print "Loop is: ", Dumper($loop);
#print "\$INC is: ", Dumper(\ %INC), "\n";
#$loop->patch();
#sleep 100;
my $loop = Mojo::IOLoop->singleton();
