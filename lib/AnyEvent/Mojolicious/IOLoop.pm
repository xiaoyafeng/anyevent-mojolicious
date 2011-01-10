package AnyEvent::Mojolicious::IOLoop;

$INC{'Mojo/IOLoop.pm'} = __FILE__;

# We have our own implementation of Mojo::IOLoop
package #don't index
	Mojo::IOLoop;

use strict;
use warnings;

# no warnings 'redefine';

use base 'Mojo::Base';

use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::DNS;

use Carp 'croak';
use File::Spec;
use IO::File;
use List::Util 'first';
use Mojo::URL;
use Scalar::Util qw(weaken refaddr);
use Socket qw/IPPROTO_TCP TCP_NODELAY SOMAXCONN SOCK_STREAM/;
use Time::HiRes 'time';

use Data::Dumper;

# Debug
use constant DEBUG => $ENV{MOJO_IOLOOP_DEBUG} || 0;

use constant TLS => $ENV{MOJO_NO_TLS}
  ? 0
  : eval 'use AnyEvent::TLS; 1';

# Windows
use constant WINDOWS => $^O eq 'MSWin32' ? 1 : 0;

# Default TLS cert (20.03.2010)
# (openssl req -new -x509 -keyout cakey.pem -out cacert.pem -nodes -days 7300)
use constant CERT => <<EOF;
-----BEGIN CERTIFICATE-----
MIIDbzCCAtigAwIBAgIJAM+kFv1MwalmMA0GCSqGSIb3DQEBBQUAMIGCMQswCQYD
VQQGEwJERTEWMBQGA1UECBMNTmllZGVyc2FjaHNlbjESMBAGA1UEBxMJSGFtYmVy
Z2VuMRQwEgYDVQQKEwtNb2pvbGljaW91czESMBAGA1UEAxMJbG9jYWxob3N0MR0w
GwYJKoZIhvcNAQkBFg5rcmFpaEBjcGFuLm9yZzAeFw0xMDAzMjAwMDQ1MDFaFw0z
MDAzMTUwMDQ1MDFaMIGCMQswCQYDVQQGEwJERTEWMBQGA1UECBMNTmllZGVyc2Fj
aHNlbjESMBAGA1UEBxMJSGFtYmVyZ2VuMRQwEgYDVQQKEwtNb2pvbGljaW91czES
MBAGA1UEAxMJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5rcmFpaEBjcGFuLm9y
ZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzu9mOiyUJB2NBuf1lZxViNM2
VISqRAoaXXGOBa6RgUoVfA/n81RQlgvVA0qCSQHC534DdYRk3CdyJR9UGPuxF8k4
CckOaHWgcJJsd8H0/q73PjbA5ItIpGTTJNh8WVpFDjHTJmQ5ihwddap4/offJxZD
dPrMFtw1ZHBRug5tHUECAwEAAaOB6jCB5zAdBgNVHQ4EFgQUo+Re5wuuzVFqH/zV
cxRGXL0j5K4wgbcGA1UdIwSBrzCBrIAUo+Re5wuuzVFqH/zVcxRGXL0j5K6hgYik
gYUwgYIxCzAJBgNVBAYTAkRFMRYwFAYDVQQIEw1OaWVkZXJzYWNoc2VuMRIwEAYD
VQQHEwlIYW1iZXJnZW4xFDASBgNVBAoTC01vam9saWNpb3VzMRIwEAYDVQQDEwls
b2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDmtyYWloQGNwYW4ub3JnggkAz6QW/UzB
qWYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQCZZcOeAobctD9wtPtO
40CKHpiGYEM3rh7VvBhjTcVnX6XlLvffIg3uTrVRhzmlEQCZz3O5TsBzfMAVnjYz
llhwgRF6Xn8ict9L8yKDoGSbw0Q7HaCb8/kOe0uKhcSDUd3PjJU0ZWgc20zcGFA9
R65bABoJ2vU1rlQFmjs0RT4UcQ==
-----END CERTIFICATE-----
EOF

# Default TLS key (20.03.2010)
# (openssl req -new -x509 -keyout cakey.pem -out cacert.pem -nodes -days 7300)
use constant KEY => <<EOF;
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDO72Y6LJQkHY0G5/WVnFWI0zZUhKpEChpdcY4FrpGBShV8D+fz
VFCWC9UDSoJJAcLnfgN1hGTcJ3IlH1QY+7EXyTgJyQ5odaBwkmx3wfT+rvc+NsDk
i0ikZNMk2HxZWkUOMdMmZDmKHB11qnj+h98nFkN0+swW3DVkcFG6Dm0dQQIDAQAB
AoGAeLmd8C51tqQu1GqbEc+E7zAZsDE9jDhArWdELfhsFvt7kUdOUN1Nrlv0x9i+
LY2Dgb44kmTM2suAgjvGulSMOYBGosZcM0w3ES76nmeAVJ1NBFhbZTCJqo9svoD/
NKdctRflUuvFSWimoui+vj9D5p/4lvAMdBHUWj5FlQsYiOECQQD/FRXtsDetptFu
Vp8Kw+6bZ5+efcjVfciTp7fQKI2xZ2n1QyloaV4zYXgDC2y3fMYuRigCGrX9XeFX
oGHGMyYFAkEAz635I8f4WQa/wvyl/SR5agtDVnkJqMHMgOuykytiF8NFbDSkJv+b
1VfyrWcfK/PVsSGBI67LCMDoP+PZBVOjDQJBAIInoCjH4aEZnYNPb5duojFpjmiw
helpZQ7yZTgxeRssSUR8IITGPuq4sSPckHyPjg/OfFuWhYXigTjU/Q7EyoECQERT
Dykna9wWLVZ/+jgLHOq3Y+L6FSRxBc/QO0LRvgblVlygAPVXmLQaqBtGVuoF4WLS
DANqSR/LH12Nn2NyPa0CQBbzoHgx2i3RncWoq1EeIg2mSMevEcjA6sxgYmsyyzlv
AnqxHi90n/p912ynLg2SjBq+03GaECeGzC/QqKK2gtA=
-----END RSA PRIVATE KEY-----
EOF

# DNS server (default to Google Public DNS)
our $DNS_SERVER = '8.8.8.8';

# Try to detect DNS server
if (-r '/etc/resolv.conf') {
	my $file = IO::File->new;
	$file->open('< /etc/resolv.conf');
	for my $line (<$file>) {
		if ($line =~ /^nameserver\s+(\S+)$/) {

			# New DNS server
			$DNS_SERVER = $1;

			# Debug
			#warn qq/DETECTED DNS SERVER ($DNS_SERVER)\n/ if DEBUG;
		}
	}
}

# "localhost"
our $LOCALHOST = '127.0.0.1';


__PACKAGE__->attr([qw/accept_timeout connect_timeout dns_timeout/] => 3);
__PACKAGE__->attr(dns_server => sub { $ENV{MOJO_DNS_SERVER} || $DNS_SERVER });
__PACKAGE__->attr(max_accepts     => 0);
__PACKAGE__->attr(max_connections => 1000);
__PACKAGE__->attr(
	[qw/on_lock on_unlock/] => sub {
		sub {1}
	}
);
__PACKAGE__->attr(timeout => '0.025');

# Singleton
our $LOOP;

# is Mojo::IOLoop already overloaded/patched?
my $_is_patched = 0;

sub DESTROY {
	my $self = shift;

	# Cleanup connections
	for my $id (keys %{$self->{_id}}) { $self->drop($id) }

	# Cleanup temporary cert file
	if (my $cert = $self->{_cert}) { unlink $cert if -w $cert }

	# Cleanup temporary key file
	if (my $key = $self->{_key}) { unlink $key if -w $key }
}

sub new {
	my $class = shift;

	print STDERR "HOHOHOHO- creating mock ioloop\n";

	# Build new loop from singleton if possible
	my $loop = $LOOP;
	local $LOOP = undef;
	my $self = $loop ? $loop->new(@_) : $class->SUPER::new(@_);

	# Ignore PIPE signal
	$SIG{PIPE} = 'IGNORE';

	# opened handles and timers...
	$self->{_id} = {};

	# AE cv...
	$self->{_cv} = undef;

	return $self;
}

sub connect {
	my $self = shift;
	print "connect called.\n";

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# TLS check
	return undef if $args->{tls} && !TLS;

	# Protocol
	$args->{proto} ||= 'tcp';

	# create handle options
	my %opt = (
		fh => delete($args->{handle}) || undef,
		connect => [delete($args->{address}), delete($args->{port})],
		tls => ($args->{tls}) ? 'connect' : undef,
	);

	# no handle?
	unless (defined $opt{fh}) {
		$opt{connect} = [$args->{address}, $args->{port}];
		delete($opt{fh});
	}

	my $id = undef;

	# on_connect
	if ($args->{on_connect} && ref($args->{on_connect}) eq 'CODE') {
		$opt{on_connect} = sub {
			$args->{on_connect}->($self, $id);
		};
	}

	# create new anyevent handle
	my $h = AnyEvent::Handle->new(%opt);

	# generate id (refaddr is 2x faster than regex)
	$id = refaddr($h);

	# save handle
	$self->{_id}->{$id} = $h;

	# callbacks...
	for my $name (qw(error hup read)) {
		my $cb    = $args->{"on_$name"};
		my $event = "on_$name";
		$self->$event($id, $cb) if (defined $cb);
	}

	return $id;
}

sub connection_timeout {
	my ($self, $id, $timeout) = @_;

	# Connection
	return unless my $c = $self->{_id}->{$id};

	return $c->timeout() unless ($timeout);

	$c->timeout($timeout);
	return $self;
}

sub drop {
	my ($self, $id) = @_;
	my $h = (exists($self->{_id}->{$id})) ? $self->{_id}->{$id} : undef;
	return undef unless (defined $h);

	# Real handle?
	if ($h->isa('AnyEvent::Handle')) {
		$h->destroy();
	}

	# delete handler
	undef $self->{_id}->{$id};
	delete($self->{_id}->{$id});

	return $self;
}

sub generate_port {
	my $self = shift;

	# Ports
	my $port = 1 . int(rand 10) . int(rand 10) . int(rand 10) . int(rand 10);
	while ($port++ < 30000) {

		# Try port
		return $port
		  if IO::Socket::INET->new(
			Listen    => 5,
			LocalAddr => '127.0.0.1',
			LocalPort => $port,
			Proto     => 'tcp'
		  );
	}

	# Nothing
	return;
}

sub is_running { shift->{_running} }

# Fat Tony is a cancer on this fair city!
# He is the cancer and I am theâ€¦ uhâ€¦ what cures cancer?
sub listen {
	my $self = shift;

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# TLS check
	croak "Net::SSLeay required for TLS support"
	  if $args->{tls} && !TLS;

	# TODO: fix id generation stuff...
	my $id = int(rand(1000000000));

	#my $id = refaddr($listener);

	# create guard object...
	my $guard = tcp_server(

		#undef,
		#5555,
		#$args->{address},
		'::',
		$args->{port},

		# accept callback
		sub {
			my ($fh, $host, $port) = @_;

			my $id = fileno($fh);

			# on accept_cb?
			if ($args->{on_accept}) {
				$args->{on_accept}->($self, $id);
			}

			#print STDERR "accept cb: ", join(", ",  @_), "\n";
			# create handle object
			my $c = AnyEvent::Handle->new(
				fh         => $fh,
				timeout    => 10,
				on_timeout => sub {
					my ($h) = @_;

					#print STDERR "ON_TIMEOUT: @_\n";
					$h->destroy();
					undef $h;
				},
				on_eof => sub {
					my ($h) = @_;

					#print STDERR "ON_EOF: @_\n";
					$args->{on_hup}->($self, $id) if ($args->{on_hup});
					$h->destroy();
				},
				on_error => sub {
					my ($h, $fatal, $msg) = @_;
					print STDERR "ON_ERROR: @_\n";
					$args->{on_error}->($self, $id, $msg)
					  if ($args->{on_error});
					$h->destroy();
				},
				on_read => sub {
					my ($h) = @_;
					
					# print "Read from $h\n";

					#my $id = refaddr($h);
					#print STDERR "ON_READ [$id]: $h\n";
					my $buf = $h->{rbuf};
					$h->{rbuf} = '';

					#print "handle: ", Dumper($_[0]), "\n";
					if ($args->{on_read}) {

						#print "Invoking read_cbbbbb\n";
						$args->{on_read}->($self, $id, $buf);
					}
				}
			);

			#my $i = refaddr($c);

			# save handle...
			$self->{_id}->{$id} = $c;

			#print "saved handle as id: $id\n";

		},
		sub {
			print "setup_CB\n";
		},
	);

	# save listener...
	$self->{_id}->{$id} = $guard;

	#print "Created guard: ", Dumper($guard), "\n";

=pod
	# TLS options
	$c->{tls} = {
		SSL_startHandshake => 0,
		SSL_cert_file      => $args->{tls_cert} || $self->_prepare_cert,
		SSL_key_file       => $args->{tls_key} || $self->_prepare_key
	  }
	  if $args->{tls};

	# Accept limit
	$self->{_accepts} = $self->max_accepts if $self->max_accepts;
=cut

	return $id;
}

sub local_info {
	my ($self, $id) = @_;

	# Connection
	return {} unless my $c = $self->{_id}->{$id};

	# Socket
	return {} unless my $socket = $c->fh();

	# UNIX domain socket info
	return {path => $socket->hostpath} if $socket->can('hostpath');

	# Info
	#return {address => $socket->sockhost, port => $socket->sockport};
	return {address => "skfdhsh", port => "kjdhkfdhd"};
}

sub lookup {
	my ($self, $name, $cb) = @_;
	return undef unless (defined $cb && ref($cb) eq 'CODE');

	# create resolver...
	my $res = AnyEvent::DNS->resolver();

	$res->resolve(
		$name, '*',
		accept => ["a", "aaaa"],
		sub {
			my @addrs = ();
			if (defined $_[0] && ref($_[0]) eq 'ARRAY') {
				map { push(@addrs, $_->[3]) } @{$_[0]};
			}

			# invoke callback...
			$cb->($self, shift(@addrs));
		},
	);
}

sub resolve {
	my ($self, $name, $type, $cb) = @_;
	return undef unless (defined $cb && ref($cb) eq 'CODE');

	# create resolver...
	my $res = AnyEvent::DNS->resolver();

	$res->resolve(
		$name, '*',
		accept => [ lc($type) ],
		sub {
			my @addrs = ();
			if (defined $_[0] && ref($_[0]) eq 'ARRAY') {
				map { push(@addrs, $_->[3]) } @{$_[0]};
			}

			# invoke callback...
			$cb->($self, shift(@addrs));
		},
	);
}

sub on_error { print "on_error: @_\n"; shift->_add_event('error', @_) }
sub on_hup   { print "on_hup: @_\n";   shift->_add_event('hup',   @_) }
sub on_idle  { print "on_idle: @_\n"; }
sub on_read  { print "on_read: @_\n"; }
sub on_tick  { print "on_tick: @_\n"; }

sub one_tick {
	my ($self, $timeout) = @_;
}

sub remote_info {
	my ($self, $id) = @_;

	# Connection
	return {} unless my $c = $self->{_id}->{$id};

	# Socket
	return {} unless my $socket = $c->{handle};

	# UNIX domain socket info
	return {path => $socket->peerpath} if $socket->can('peerpath');

	# Info
	return {address => $socket->peerhost, port => $socket->peerport};
}

sub singleton { $LOOP ||= shift->new(@_) }

sub start {
	my $self = shift;

	# create condvar...
	$self->{_cv} = AnyEvent->condvar();

	# wait for completion...
	$self->{_cv}->recv();
	delete($self->{_cv});

	return $self;
}

sub start_tls {
	my $self = shift;
	my $id   = shift;

	# Shortcut
	$self->drop($id) and return unless TLS;

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# Weaken
	weaken $self;

	return $id;
}

sub stop {
	my $self = shift;
	return $self unless (defined $self->{_cv});
	
	$self->{_cv}->send();
	return $self;
}

sub test {
	my ($self, $id) = @_;

	# Connection
	return unless my $c = $self->{_id}->{$id};

	# Socket
	return unless my $socket = $c->{handle};

	my $result = 1;

=pod
	# Test
	my $test = $self->{_test} ||= IO::Poll->new;
	$test->mask($socket, POLLIN);
	$test->poll(0);
	my $result = $test->handles(POLLIN | POLLERR | POLLHUP);
	$test->remove($socket);
=cut

	return !$result;
}

# compatibility method for Mojo::Server::Daemon
sub _drop_immediately {
	my ($self, $id) = @_;
	return $self->drop($id);
}

sub timer {
	my ($self, $after, $cb) = @_;
	return undef unless (defined $cb && ref($cb) eq 'CODE');
	my $id = _newId();

	# create AnyEvent timer
	my $timer = AnyEvent->timer(
		after => $after,
		cb    => sub {

			# drop timer...
			undef $self->{_id}->{$id};
			delete($self->{_id}->{$id});

			# invoke callback...
			$cb->();
		},
	);

	# save timer
	$self->{_id}->{$id} = $timer;

	# return id
	return $id;
}

sub write {
	my ($self, $id, $chunk, $cb) = @_;
	my $h = $self->{_id}->{$id};
	return unless (defined $h);
	$h->push_write($chunk);

	# write done callback...
	if ($cb) {
		$h->on_drain(sub { $cb->($self, $id) });
	}

	return $self;
}


sub _prepare_cert {
	my $self = shift;

	# Shortcut
	my $cert = $self->{_cert};
	return $cert if $cert && -r $cert;

	# Create temporary TLS cert file
	$cert = File::Spec->catfile($ENV{MOJO_TMPDIR} || File::Spec->tmpdir,
		'mojocert.pem');
	my $file = IO::File->new;
	$file->open("> $cert")
	  or croak qq/Can't create temporary TLS cert file "$cert"/;
	print $file CERT;

	return $self->{_cert} = $cert;
}

sub _prepare_key {
	my $self = shift;

	# Shortcut
	my $key = $self->{_key};
	return $key if $key && -r $key;

	# Create temporary TLS key file
	$key = File::Spec->catfile($ENV{MOJO_TMPDIR} || File::Spec->tmpdir,
		'mojokey.pem');
	my $file = IO::File->new;
	$file->open("> $key")
	  or croak qq/Can't create temporary TLS key file "$key"/;
	print $file KEY;

	return $self->{_key} = $key;
}

sub patch {
	return 1 if ($_is_patched);
	
	if (exists($INC{'Mojo/IOLoop.pm'})) {
		print "IOLoop is already loaded, will replace it's methods.\n";
		$INC{'Mojo/IOLoopOrig.pm'} = $INC{'Mojo/IOLoop.pm'};
	} else {
		print "IOLoop is NOT loaded, will create it...\n";
		$INC{'Mojo/IOLoop.pm'} = __FILE__;
	}


	use Data::Dumper;
	#$Data::Dumper::Indent = 0;
	#$Data::Dumper::Terse = 1;
	
	print "PKG: ", Dumper(\ %{AnyEvent::Mojolicious::IOLoop::}), "\n";

	# copy subs...
	for (keys %{AnyEvent::Mojolicious::IOLoop::}) {

		no strict 'refs';
		no warnings 'redefine';
		print "key: $_\n";

		my $sub = undef;
		eval { $sub = *{$AnyEvent::Mojolicious::IOLoop::{$_}{CODE}} };
		next if ($@);
		
		print "SUB: $sub :: ", Dumper($sub), "\n";

		next;
	}

	$_is_patched = 1;
	return 1;
}

sub _newId {
	return sprintf("%-.7d", int(time()) + int(rand(10000000)));
}

1;

# EOF