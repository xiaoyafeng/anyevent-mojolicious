package Mojo::Command::DaemonAnyevent;

use strict;
use warnings;

use Getopt::Long;

use Mojo::Server::DaemonAnyevent;

use base 'Mojolicious::Command::Daemon';

__PACKAGE__->attr(description => <<'EOF');
Start application with HTTP 1.1 and WebSocket server powered by AnyEvent.
EOF

sub run {
  my $self   = shift;
  my $daemon = Mojo::Server::DaemonAnyevent->new;

  # Options
  local @ARGV = @_ if @_;
  my @listen;
  GetOptions(
    'backlog=i'   => sub { $daemon->backlog($_[1]) },
    'clients=i'   => sub { $daemon->max_clients($_[1]) },
    'group=s'     => sub { $daemon->group($_[1]) },
    'keepalive=i' => sub { $daemon->keep_alive_timeout($_[1]) },
    'listen=s'    => \@listen,
    'proxy'       => sub { $ENV{MOJO_REVERSE_PROXY} = 1 },
    'reload'      => sub { $ENV{MOJO_RELOAD}        = 1 },
    'requests=i'  => sub { $daemon->max_requests($_[1]) },
    'user=s'      => sub { $daemon->user($_[1]) },
    'websocket=i' => sub { $daemon->websocket_timeout($_[1]) }
  );
  $daemon->listen(\@listen) if @listen;

  # Run
  $daemon->run;

  return $self;
}

1;