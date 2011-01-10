package Mojo::Command::DaemonAnyevent;

use strict;
use warnings;

use AnyEvent::Mojolicious::IOLoop;
use Mojo::Server::DaemonAnyevent;

use base 'Mojo::Command::Daemon';

__PACKAGE__->attr(description => <<'EOF');
Start application with HTTP 1.1 and WebSocket server based on AnyEvent.
EOF

1;