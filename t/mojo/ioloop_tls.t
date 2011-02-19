#!/usr/bin/env perl

use strict;
use warnings;

# Disable epoll and kqueue
BEGIN { $ENV{MOJO_POLL} = 1 }

# To regenerate all required certificates run these commands
# openssl genrsa -out ca.key 1024
# openssl req -new -key ca.key -out ca.csr -subj "/C=US/CN=ca"
# openssl req -x509 -days 7300 -key ca.key -in ca.csr -out ca.crt
#
# openssl genrsa -out server.key 1024
# openssl req -new -key server.key -out server.csr -subj "/C=US/CN=server"
# openssl x509 -req -days 7300 -in server.csr -out server.crt -CA ca.crt \
#   -CAkey ca.key -CAcreateserial
#
# openssl genrsa -out client.key 1024
# openssl req -new -key client.key -out client.csr -subj "/C=US/CN=client"
# openssl x509 -req -days 7300 -in client.csr -out client.crt -CA ca.crt \
#   -CAkey ca.key -CAcreateserial
#
# openssl genrsa -out badclient.key 1024
# openssl req -new -key badclient.key -out badclient.csr \
#   -subj "/C=US/CN=badclient"
# openssl req -x509 -days 7300 -key badclient.key -in badclient.csr \
#   -out badclient.crt
use Test::More;
use AnyEvent::Mojolicious::IOLoop;
plan skip_all => 'AnyEvent::TLS required for this test!'
  unless Mojo::IOLoop::TLS;
plan skip_all => 'Windows is too fragile for this test!'
  if Mojo::IOLoop::WINDOWS;
plan tests => 14;

# "To the panic room!
#  We don't have a panic room.
#  To the panic room store!"
my $loop = Mojo::IOLoop->new;
my $port = Mojo::IOLoop->generate_port;
my ($server, $client) = '';
$loop->listen(
  port      => $port,
  tls       => 1,
  on_accept => sub {
    shift->write(shift, 'test', sub { shift->write(shift, '321') });
  },
  on_read => sub { $server .= pop },
  on_hup  => sub { $server .= 'hup' }
);
my $id = $loop->connect(
  address    => 'localhost',
  port       => $port,
  tls        => 1,
  on_connect => sub {
    shift->write(shift, 'tset', sub { shift->write(shift, '123') });
  },
  on_read => sub { $client .= pop },
  on_hup => sub { shift->stop }
);
$loop->connection_timeout($id => '0.5');
$loop->start;
is $server, 'tset123hup', 'right content';
is $client, 'test321',    'right content';

# Valid client certificate
$loop   = Mojo::IOLoop->new;
$port   = Mojo::IOLoop->generate_port;
$server = $client = '';
my $error = '';
$loop->listen(
  port      => $port,
  tls       => 1,
  tls_cert  => 't/mojo/certs/server.crt',
  tls_key   => 't/mojo/certs/server.key',
  tls_ca    => 't/mojo/certs/ca.crt',
  on_accept => sub {
    shift->write(shift, 'test', sub { shift->write(shift, '321') });
  },
  on_read => sub { $server .= pop },
  on_hup  => sub { $server .= 'hup' },
  on_error => sub { $error = pop },
);
$id = $loop->connect(
  address    => 'localhost',
  port       => $port,
  tls        => 1,
  tls_cert   => 't/mojo/certs/client.crt',
  tls_key    => 't/mojo/certs/client.key',
  on_connect => sub {
    shift->write(shift, 'tset', sub { shift->write(shift, '123') });
  },
  on_read => sub { $client .= pop },
  on_hup => sub { shift->stop },
);
$loop->connection_timeout($id => '0.5');
$loop->timer(1 => sub { shift->stop });
$loop->start;
is $server, 'tset123hup', 'right content';
is $client, 'test321',    'right content';
ok !$error, 'no error';

# Invalid client certificate
$error = '';
$id    = $loop->connect(
  address  => 'localhost',
  port     => $port,
  tls      => 1,
  tls_cert => 't/mojo/certs/badcert.key',
  tls_key  => 't/mojo/certs/badcert.crt',
  on_error => sub { $error = pop },
);
$loop->connection_timeout($id => '0.5');
$loop->timer(1 => sub { shift->stop });
$loop->start;
ok $error, 'has error';

# Valid client certificate but rejected by callback
$loop = Mojo::IOLoop->new;
$port = Mojo::IOLoop->generate_port;
my $cerror = $error = '';
$loop->listen(
  port       => $port,
  tls        => 1,
  tls_cert   => 't/mojo/certs/server.crt',
  tls_key    => 't/mojo/certs/server.key',
  tls_ca     => 't/mojo/certs/ca.crt',
  tls_verify => sub {0},
  on_error   => sub { $error = pop },
);
$id = $loop->connect(
  address  => 'localhost',
  port     => $port,
  tls      => 1,
  tls_cert => 't/mojo/certs/client.crt',
  tls_key  => 't/mojo/certs/client.key',
  on_error => sub { $cerror = pop }
);
$loop->connection_timeout($id => '0.5');
$loop->timer(1 => sub { shift->stop });
$loop->start;
ok $error,  'has error';
ok $cerror, 'has error';

# Valid client certificate accepted by callback
$loop   = Mojo::IOLoop->new;
$port   = Mojo::IOLoop->generate_port;
$server = $client = '';
$loop->listen(
  port       => $port,
  tls        => 1,
  tls_cert   => 't/mojo/certs/server.crt',
  tls_key    => 't/mojo/certs/server.key',
  tls_ca     => 't/mojo/certs/ca.crt',
  tls_verify => sub {1},
  on_accept  => sub {
    shift->write(shift, 'test', sub { shift->write(shift, '321') });
  },
  on_read => sub { $server .= pop },
  on_hup  => sub { $server .= 'hup' },
  on_error => sub { $error = pop }
);
$id = $loop->connect(
  address    => 'localhost',
  port       => $port,
  tls        => 1,
  tls_cert   => 't/mojo/certs/client.crt',
  tls_key    => 't/mojo/certs/client.key',
  on_connect => sub {
    shift->write(shift, 'tset', sub { shift->write(shift, '123') });
  },
  on_read => sub { $client .= pop },
  on_hup => sub { shift->stop },
);
$loop->connection_timeout($id => '0.5');
$loop->timer(1 => sub { shift->stop });
$loop->start;
is $server, 'tset123hup', 'right content';
is $client, 'test321',    'right content';

# Missing client certificate
$error = $cerror = '';
$id = $loop->connect(
  address  => 'localhost',
  port     => $port,
  tls      => 1,
  on_error => sub { $cerror = pop }
);
$loop->connection_timeout($id => '0.5');
$loop->start;
ok $error,  'has error';
ok $cerror, 'has error';

# Invalid certificate authority
$loop  = Mojo::IOLoop->new;
$port  = Mojo::IOLoop->generate_port;
$error = $cerror = '';
$loop->listen(
  port      => $port,
  tls       => 1,
  tls_cert  => 't/mojo/certs/server.crt',
  tls_key   => 't/mojo/certs/server.key',
  tls_ca    => 'no cert',
  on_accept => sub {
    shift->write(shift, 'test', sub { shift->write(shift, '321') });
  },
  on_error => sub { $error = pop }
);
$id = $loop->connect(
  address  => 'localhost',
  port     => $port,
  tls      => 1,
  tls_cert => 't/mojo/certs/client.crt',
  tls_key  => 't/mojo/certs/client.key',
  on_error => sub { $cerror = pop }
);
$loop->connection_timeout($id => '0.5');
$loop->timer(1 => sub { shift->stop });
$loop->start;
ok $error,  'has error';
ok $cerror, 'has error';
