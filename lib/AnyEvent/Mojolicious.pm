package AnyEvent::Mojolicious;

use strict;
use warnings;

# load the ioloop
use AnyEvent::Mojolicious::IOLoop;
use Mojo::Server::DaemonAnyevent;

our $VERSION = 0.10;

=head1 NAME

Get more Mojo with AnyEvent, bring even more mojo to AnyEvent!

=head1 DESCRIPTION

The aim of this module is to bring all the good stuff provided by
L<AnyEvent> to L<Mojolicious> webapplication framework and vice versa. You can use
rich collection of L<AnyEvent modules found on CPAN|http://search.cpan.org/search?m=all&q=AnyEvent&s=21>
in your mojo webapps, or you can use some of really cool features found in Mojolicious in your
standalone AnyEvent application.

Great Mojolicious features worth including in your anyevent program:

=over

=item L<TLS, IPv6 and websocket capable HTTP/1.1 server|Mojo::Server::Daemon>

=item L<TLS, IPv6 and websocket capable HTTP/1.1 client|Mojo::UserAgent>

=back

=head1 SYNOPSIS

 # Automatically loads AnyEvent::Mojolicious::IOLoop
 use AnyEvent::Mojolicious;

=head2 Run Mojolicious webapp in standalone AnyEvent program

 # create http server
 my $mojo_http = Mojo::Server::DaemonAnyevent->new();
 
 # add listening sockets...
 $mojo_httpd->listen([ 'https://[::]:3003', 'http://*:3000' ]);
 
 # set application class
 $mojo_httpd->app_class('MyApp');
 
 # start it!
 $mojo_httpd->run();

Ofcourse you can start multiple instances of http server, each running different webapp, plus
you can start or stop them anytime in lifetime of your perl program.


=head2 Use cool features of Mojo::Server::Daemon in standalonne AnyEvent program

 # create http server
 my $mojo_http = Mojo::Server::DaemonAnyevent->new();
 
 # add listening sockets...
 $mojo_httpd->listen([ 'https://[::]:3003', 'http://*:3000' ]);
 
 # add some custom url handlers
 $mojo_httpd->handler_add(
   # URI regex
   qr/^\/+ae/,
  
   # URI handler callback
   sub {
     my ($self, $tx) = @_;
     $tx->res->code(200);
     $tx->res->headers->content_type('text/plain; charset=utf-8');
     $tx->res->body('Hello world @ ' . time());
   
     # mark transaction as done.
     $tx->resume;
   }
 );
 
 # start it!
 $mojo_httpd->run();
 
=head2 Add AnyEvent features to your mojolicious webapp

Create Mojo webapp the way you always do: 

 # file: webapp.pl
 use strict;
 use warnings;

 use AnyEvent;
 use Mojolicious::Lite;
 
 get '/ae' => sub {
	my $self = shift;	
	my $delay = rand(0.77);
	my $t = AE::timer(
	  $delay,
	  0,
	  sub {
	    $self->render(data => 'hello with some delay: ' . $delay);
	  }
	);
	$self->stash(timer => $t);
 };
 
 app->start;

Run your webapp with daemon_anyevent server mode:

 $ ./webapp.pl daemon_anyevent 

=head1 SEE ALSO

=over

=item L<AnyEvent::Mojolicious::IOLoop>

L<Mojo::IOLoop> re-implementation powered by L<AnyEvent>.

=item L<Mojo::Server::DaemonAnyevent>

L<Mojo::Server::Daemon> extension.

=item L<Mojolicious>

=item L<AnyEvent>

=item L<EV>

Fastest event-loop engine for L<AnyEvent>.

=back

=head1 ACKNOWLEDGEMENTS

=over

=item L<Class::Unload> by Dagfinn Ilmari Mannsåker

=item L<Class::Inspector> by Adam Kennedy
 
L<AnyEvent::Mojolicious::IOLoop> uses slightly modified code from L<Class::Unload>
and L<Class::Inspector> to unload L<Mojo::IOLoop> class in runtime in order to replace it
with it's own implementation.  

=back

=head1 BUGS

Please report any bugs or feature requests to C<bug-AnyEvent-Mojolicious at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=AnyEvent-Mojolicious>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc AnyEvent::Mojolicious

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=AnyEvent-Mojolicious>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/AnyEvent-Mojolicious>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/AnyEvent-Mojolicious>

=item * Search CPAN

L<http://search.cpan.org/dist/AnyEvent-Mojolicious/>

=item * Source repository

L<https://github.com/bfg/anyevent-mojolicious>

=back

=head1 AUTHOR

Brane F. Gracnar

=head1 LICENSE AND COPYRIGHT

Copyright 2011, Brane F. Gracnar.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;