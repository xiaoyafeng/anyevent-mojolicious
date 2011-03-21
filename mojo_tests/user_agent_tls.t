#!/usr/bin/env perl

use strict;
use warnings;

use AnyEvent::Mojolicious;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
use Mojo::IOLoop;
plan skip_all => 'IO::Socket::SSL 1.37 required for this test!'
  unless Mojo::IOLoop::TLS;
plan tests => 9;

# "That does not compute.
#  Really?
#  Well, it computes a little."
use Mojo::UserAgent;

# User agent
my $ua = Mojo::UserAgent->new;

# Silence
$ua->log->level('fatal');

# Server
my $port = $ua->ioloop->generate_port;
my $error;
my $id = $ua->ioloop->listen(
  port     => $port,
  tls      => 1,
  tls_cert => 't/mojo/certs/server.crt',
  tls_key  => 't/mojo/certs/server.key',
  tls_ca   => 't/mojo/certs/ca.crt',
  on_read  => sub {
    my ($loop, $id) = @_;
    $loop->write($id => "HTTP/1.1 200 OK\x0d\x0a"
        . "Connection: keep-alive\x0d\x0a"
        . "Content-Length: 6\x0d\x0a\x0d\x0aworks!");
    $loop->drop($id);
  },
  on_error => sub {
    shift->drop(shift);
    $error = shift;
  }
);

# No certificate
my $tx = $ua->get("https://localhost:$port");
ok !$tx->success, 'not successful';
ok $error, 'has error';
$error = '';
$tx    = $ua->cert('')->key('')->get("https://localhost:$port");
ok !$tx->success, 'not successful';
ok $error, 'has error';

# Valid certificate
$tx =
  $ua->cert('t/mojo/certs/client.crt')->key('t/mojo/certs/client.key')
  ->get("https://localhost:$port");
ok $tx->success, 'successful';
is $tx->res->code, 200,      'right status';
is $tx->res->body, 'works!', 'right content';

# Invalid certificate
$tx =
  $ua->cert('t/mojo/certs/badclient.crt')->key('t/mojo/certs/badclient.key')
  ->get("https://localhost:$port");
ok $error, 'has error';

# Empty certificate
$tx = $ua->cert('no file')->key('no file')->get("https://localhost:$port");
ok $error, 'has error';
