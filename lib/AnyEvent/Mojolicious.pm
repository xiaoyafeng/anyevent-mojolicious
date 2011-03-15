package AnyEvent::Mojolicious;

use strict;
use warnings;

#no warnings 'redefine';

# load the ioloop
use AnyEvent::Mojolicious::IOLoop;
use Mojo::Server::DaemonAnyevent;

our $VERSION = 0.10;

=head1 NAME

Get more Mojo with AnyEvent!

=head1 SYNOPSIS

 use AnyEvent;
 use AnyEvent::Mojolicious;

=head1 SEE ALSO

L<Mojolicious>, L<Mojo::IOLoop>, L<AnyEvent>, L<EV>

=head1 AUTHOR

Brane F. Gracnar

=cut