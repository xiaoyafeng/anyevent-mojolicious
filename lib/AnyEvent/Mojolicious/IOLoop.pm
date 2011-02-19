package AnyEvent::Mojolicious::IOLoop;

use strict;
use warnings;

use Carp 'carp';

# is mojo::ioloop already loaded?
if (exists($INC{'Mojo/IOLoop.pm'})) {
	_unload('Mojo/IOLoop.pm');
}
else {

	# let's just pretend that we are THE Mojo::IOLoop :)
	#print "Faking ioloop...\n";
}

# we are THE IOLoop :P
$INC{'Mojo/IOLoop.pm'} = __FILE__;

#
# This function is TOTALY STOLEN FROM Mojo::Loader!
#
sub _unload {
	my $key  = shift;
	my $file = $INC{$key};
	delete $INC{$key};
	return unless $file;
	my @subs = grep { index($DB::sub{$_}, "$file:") == 0 } keys %DB::sub;
	for my $sub (@subs) {
		eval { undef &$sub };
		delete $DB::sub{$sub};
	}
}

package Mojo::IOLoop;

use strict;
use warnings;

# omfg!
no warnings 'redefine';

use Carp 'croak';
use File::Spec;
use IO::File;
use Scalar::Util qw(weaken refaddr blessed);

use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::DNS;

# use Socket qw(IPPROTO_TCP TCP_NODELAY SO_REUSEADDR);

use base 'Mojo::Base';

# Debug
use constant DEBUG => $ENV{MOJO_IOLOOP_DEBUG} || 0;

# TLS support requires IO::Socket::SSL
use constant TLS => $ENV{MOJO_NO_TLS}
  ? 0
  : eval 'use AnyEvent::TLS; 1';

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

__PACKAGE__->attr([qw/accept_timeout connect_timeout dns_timeout/] => 3);
__PACKAGE__->attr(dns_server => sub { $ENV{MOJO_DNS_SERVER} });
__PACKAGE__->attr(max_accepts     => 0);
__PACKAGE__->attr(max_connections => 1000);
__PACKAGE__->attr([qw/on_lock on_unlock/] => sub {
	sub {1}
});
__PACKAGE__->attr(timeout => '0.025');

# Singleton
our $LOOP;

sub DESTROY {
	my $self = shift;

	# Cleanup connections
	for my $id (keys %{$self->{_cs}}) { $self->_drop_immediately($id) }

	# Cleanup listen sockets
	for my $id (keys %{$self->{_listen}}) { $self->_drop_immediately($id) }

	# Cleanup temporary cert file
	if (my $cert = $self->{_cert}) { unlink $cert if -w $cert }

	# Cleanup temporary key file
	if (my $key = $self->{_key}) { unlink $key if -w $key }
}

sub new {
	my $class = shift;

	# Build new loop from singleton if possible
	my $loop = $LOOP;
	local $LOOP = undef;
	my $self = $loop ? $loop->new(@_) : $class->SUPER::new(@_);

	# Ignore PIPE signal
	$SIG{PIPE} = 'IGNORE';
	return $self;
}

sub connect {
	my $self = shift;

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# Protocol
	$args->{proto} ||= 'tcp';

	if (lc($args->{proto}) ne 'tcp') {
		croak "Unsupported protocol: $args->{proto}";
	}

	# connection structure
	my $conn = {
		g => undef,    # guard object
		h => undef,    # handle object
	};

	# compute id and save it
	my $id = refaddr($conn);
	$self->{_cs}->{$id} = $conn;

	my $on_connect = delete($args->{on_connect});
	$on_connect = undef unless (ref($on_connect) eq 'CODE');

	# do we have handle?
	my $handle = delete($args->{handle}) || delete($args->{socket}) || undef;

	# socket/handle?
	if (defined $handle) {

		# create anyevent handle right away!
		$self->{_cs}->{$id}->{h} = AnyEvent::Handle->new(
			fh       => $handle,
			no_delay => 1,
		);
		$self->{_cs}->{$id}->{h}->on_connect(sub { $on_connect->($self, $id) })
		  if ($on_connect);

		# register callbacks
		for my $name (qw/error hup read/) {
			my $cb    = $args->{"on_$name"};
			my $event = "on_$name";
			$self->$event($id => $cb) if $cb;
		}
	}

	# nop, someone wants real connection
	else {

		# Remove [] from address (ipv6 stuff)
		$args->{address} =~ s/[\[\]]+//g;

		# create connection guard...
		$conn->{g} = tcp_connect(
			$args->{address},
			$args->{port},

			# connect callback
			sub {
				my ($fh, $host, $port, $retry) = @_;

				# connect failed?
				unless (defined $fh) {

					# invoke error callback
					if (ref($args->{on_error}) eq 'CODE') {
						$args->{on_error}->($self, $id, "$!");
					}

					# destroy handle
					$self->drop($id);
					return;
				}

				# connect succeeded, time to create handle
				$self->{_cs}->{$id}->{h} = AnyEvent::Handle->new(
					fh => $fh,
					no_delay => 1,
					on_connect => sub {
						$on_connect->($self, $id) if ($on_connect)
					}
				);

				# register callbacks
				for my $name (qw/error hup read/) {
					my $cb    = $args->{"on_$name"};
					my $event = "on_$name";
					$self->$event($id => $cb) if $cb;
				}

				# TLS?
				if ($args->{tls}) { $self->start_tls($id => $args) }
			},

			# prepare callback
			sub {

				# my ($sock) = @_;
				# return connect timeout
				return $self->connect_timeout();
			}
		);
	}

	return $id;
}

sub connection_timeout {
	my ($self, $id, $timeout) = @_;
	return unless (defined $id && exists($self->{_cs}->{$id}));
	my $h = $self->{_cs}->{$id}->{h};
	return unless ($h);

	if ($timeout) {
		$h->timeout($timeout);
		return $self;
	}

	return $h->timeout();
}

sub drop {
	my ($self, $id) = @_;
	my $c = $self->{_cs}->{$id};
	return 0 unless (defined $id);

	# drop handle
	if (ref($c) eq 'HASH') {
		if (defined $c->{h}) {
			$c->{h}->destroy();
			$c->{h} = undef;
		}

		# drop guard
		if (defined $c->{g}) {
			$c->{g} = undef;
		}
	}

	# drop it...
	delete($self->{_cs}->{$id});

=pod
  # Drop connection gracefully
  if (my $c = $self->{_cs}->{$id}) { return $c->{finish} = 1 }

  # Drop
  return $self->_drop_immediately($id);
=cut

}

sub _drop_immediately { drop(@_) }

sub generate_port {
	my $self = shift;

	# Ports
	my $port = 1 . int(rand 10) . int(rand 10) . int(rand 10) . int(rand 10);
	eval { require IO::Socket::INET };
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

# "Fat Tony is a cancer on this fair city!
#  He is the cancer and I am the… uh… what cures cancer?"
sub listen {
	my $self = shift;

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# TLS check
	croak "AnyEvent::TLS required for TLS support"
	  if $args->{tls} && !TLS;


	my $listen = {
		g => undef,
		h => undef,
	};
	my $id = refaddr($listen);
	$self->{_cs}->{$id} = $listen;

	my $addr = undef;
	my $port = undef;
	if ($args->{file}) {
		$addr = 'unix/';
		$port = $args->{file};
	}
	elsif ($args->{address}) {
		$addr = delete($args->{address});
		$addr = s/[\[\]]+//g;
		$port = delete($args->{port}) || 3000;
	}
	else {
		$addr = undef;
		$port = delete($args->{port}) || 3000;
	}

	my $on_accept = delete($args->{on_accept});
	unless (ref($on_accept) eq 'CODE') {
		croak "No on_accept defined!";
		return;
	}

	# create tcp server
	$listen->{g} = tcp_server(
		$addr,
		$port,

		# accept cb
		sub {

			# TODO: handle max_accepts!
			my ($fh, $host, $port) = @_;
			print "accept: $fh, $host, $port\n" if DEBUG;

			# time to create client handle!
			my $ch = AnyEvent::Handle->new(fh => $fh, no_delay => 1);
			my $cid = refaddr($ch);
			
			# set connection timeout
			$ch->on_rtimeout(sub { $args->{on_hup}->($self, $cid) }) if ($args->{on_hup});
			$ch->rtimeout($self->connection_timeout());

			# save handle
			$self->{_cs}->{$cid} = {h => $ch};

			# apply callbacks
			for my $name (qw/error hup read/) {
				my $cb    = $args->{"on_$name"};
				my $event = "on_$name";
				$self->$event($cid => $cb) if $cb;
			}

			# TLS?
			if ($args->{tls}) {
				my $ca = $args->{tls_ca};
				my $ca_is_file = (defined $ca && -T $ca) ? 1 : 0;
				$ch->starttls(
					'accept',
					{   sslv2     => 0,
						sslv3     => 1,
						tlsv1     => 1,
						cert_file => $args->{tls_cert}
						  || $self->_prepare_cert(),
						key_file => $args->{tls_key} || $self->_prepare_key(),
						verify             => ($ca)         ? 1     : 0,
						verify_client_cert => ($ca)         ? 1     : 0,
						verify_peername    => 'http',
						ca_file            => ($ca_is_file) ? $ca   : undef,
						ca_path            => ($ca_is_file) ? undef : $ca,
						check_crl => (defined $args->{tls_crl} && -T $args->{tls_crl})
						? $args->{tls_crl}
						: undef,
					},
				);

			}

			# fire on_accept handler!
			$on_accept->($self, $cid);
		},

		# prepare cb
		sub {

			#my ($fh, $host, $port) = @_;
			#tcp_nodelay $fh, 1;
			# setsockopt($fh, IPPROTO_TCP, SO_REUSEADDR, 1);
		}
	);

	return $id;
}

sub local_info {
	my ($self, $id) = @_;
	return {} unless (defined $id && exists($self->{_cs}->{$id}));
	my $h = $self->{_cs}->{$id}->{h};
	my $socket =
	  (defined $h && blessed($h) && $h->isa('AnyEvent::Handle'))
	  ? $h->fh()
	  : undef;
	return {} unless ($socket);

	# UNIX domain socket info
	return {path => $socket->hostpath} if $socket->can('hostpath');

	# Info
	# return {address => $socket->sockhost, port => $socket->sockport};
	# TODO: fix this
	return {address => "skfdhsh", port => "kjdhkfdhd"};
}

sub lookup {
	my ($self, $name, $cb) = @_;

	# create resolver
	my $res = AnyEvent::DNS::resolver();
	$res->timeout([$self->dns_timeout()]);

	weaken $self;

	# fire dns request!
	$res->resolve(
		$name, '*',
		accept => ["a", "aaaa"],
		sub {
			my $res = [];
			map { push(@{$res}, $_->[3]) } @_;

			# fire cb
			$cb->($self, $res);
		},
	);

	return $self;
}

sub on_error {
	my ($self, $id, $cb) = @_;
	return unless (exists $self->{_cs}->{$id});
	my $h = $self->{_cs}->{$id}->{h};
	return unless (defined $h);

	weaken $self;

	# set callback
	$h->on_error(
		sub {
			my ($hdl, $fatal, $msg) = @_;
			print "error on $id: $msg\n" if DEBUG;
			$cb->($self, $id, $msg);
			$self->drop($id);
		}
	);

	return $self;
}

sub on_hup {
	my ($self, $id, $cb) = @_;
	return unless (exists $self->{_cs}->{$id});
	my $h = $self->{_cs}->{$id}->{h};
	return unless (defined $h);

	weaken $self;

	# set callback
	$h->on_eof(
		sub {
			my ($hdl) = @_;
			print "hup on $id\n" if DEBUG;
			$cb->($self, $id);
			$self->drop($id);
		}
	);

	return $self;
}

sub on_idle {
	my ($self, $cb) = @_;
	print "idle\n" if (DEBUG);
	my $idle = AE::idle $cb;
	my $id   = refaddr($idle);
	$self->{_cs}->{$id} = $idle;
	return $self;
}

sub on_read {
	my ($self, $id, $cb) = @_;
	return unless (exists $self->{_cs}->{$id});
	my $h = $self->{_cs}->{$id}->{h};
	return unless (defined $h);

	weaken $self;

	# set callback
	$h->on_read(
		sub {
			print "read on $id\n" if DEBUG;
			my ($h) = @_;
			$cb->($self, $id, $h->{rbuf});
			$h->{rbuf} = '';
		}
	);

	return $self;
}

sub on_tick {
	my ($self, $cb) = @_;
	if ($cb && $self->timeout) {
		my $c = {
			g => undef,
			t => AE::timer(0.01, $self->timeout(), $cb)
		};
		my $id = refaddr($c);
		$self->{_cs}->{$id} = $c;
	}
	#croak 'on_tick is not supported in ' . ref($self);
	return $self;
}

sub one_tick {
	my ($self, $timeout) = @_;
	croak 'one_tick is not supported in ' . ref($self);
}

sub handle {
	my ($self, $id) = @_;
	return unless my $c = $self->{_cs}->{$id};
	return unless (ref($c) eq 'HASH' && $c->{h});
	return $c->{h}->fh();
}

sub remote_info {
	my ($self, $id) = @_;
	return {} unless my $c = $self->{_cs}->{$id};
	return {} unless (ref($c) eq 'HASH' && $c->{h});

	my $socket =
	  (blessed($c) && $c->isa('AnyEvent::Handle')) ? $c->fh() : undef;

	# Socket
	return {} unless (defined $socket);

	# UNIX domain socket info
	return {path => $socket->peerpath} if $socket->can('peerpath');

	# Info
	return {address => $socket->peerhost, port => $socket->peerport}
	  if ($socket->can('peerhost'));
}

sub resolve {
	my ($self, $name, $type, $cb) = @_;

	# create resolver
	my $res = AnyEvent::DNS::resolver();
	$res->timeout([$self->dns_timeout()]);

	# fire dns request!
	$res->resolve(
		$name, $type,
		sub {
			#use Data::Dumper;
			#print STDERR "RESOLVE CB_ ", Dumper(\ @_), "\n";
			my $res = [];
			map { push(@{$res}, [ $_->[1], $_->[3] ]) } $_[0];

			# fire cb
			$cb->($self, $res);
		},
	);

	return $self;
}

sub singleton { $LOOP ||= shift->new(@_) }

sub start {
	my $self = shift;
	return if ($self->{_running});

# create condvar...
# TODO: beware of this monster!
# http://search.cpan.org/~mlehmann/AnyEvent-5.31/lib/AnyEvent/FAQ.pod#Why_do_some_backends_use_a_lot_of_CPU_in_AE::cv->recv?
	$self->{_cv} = AnyEvent->condvar();

	# we're now running
	$self->{_running} = 1;

	# wait for completion...
	$self->{_cv}->recv();
	delete($self->{_cv});

	print "LOOP $self started!\n" if DEBUG;
	return $self;
}

sub start_tls {
	my $self = shift;
	my $id   = shift;
	return unless (exists $self->{_cs}->{$id});

	# No TLS support
	unless (TLS) {
		$self->_error($id, 'AnyEvent::TLS required for TLS support.');
		return;
	}

	# Arguments
	my $args = ref $_[0] ? $_[0] : {@_};

	# Weaken
	weaken $self;

	# get handle
	my $h = $self->{_cs}->{$id}->{h};
	return unless (defined $h);
	
	my $opt = {
		sslv2 => 0,
		sslv3 => 1,
		tlsv1 => 1,
	};
	# key/cert
	$opt->{key_file} = $args->{tls_key} if ($args->{tls_key});
	$opt->{cert_file} = $args->{tls_key} if ($args->{tls_cert});

	# start tls...
	$h->starttls('connect', $opt);

	return $id;
}

sub stop {
	my ($self) = @_;
	return unless ($self->{_running});
	return unless (defined $self->{_cv});

	$self->{_cv}->send();
	delete($self->{_cv});
	$self->{_running} = 0;
}

sub test {
	my ($self, $id) = @_;
	croak 'Method test is not implemented in ' . ref($self);
}

sub timer {
	my ($self, $after, $cb) = @_;
	weaken $self;
	my $t = AE::timer($after, 0, sub { print STDERR "exec timer.\n"; $cb->($self) });
	my $id = refaddr($t);

	# save it...
	$self->{_cs}->{$id} = $t;
	return $id;
}

sub write {
	my ($self, $id, $chunk, $cb) = @_;
	return unless (exists $self->{_cs}->{$id});
	my $h = $self->{_cs}->{$id}->{h};
	return unless (defined $h);

	# write done callback...
	if ($cb) {
		$h->on_drain(sub { $cb->($self, $id) });
	}

	# add chunk for writing...
	$h->push_write($chunk);


	return $self;
}

sub _error {
	my ($self, $id, $error) = @_;

	# Connection
	return unless my $c = $self->{_cs}->{$id};

	# Get error callback
	my $event = $c->{error};

	# Cleanup
	$self->_drop_immediately($id);

	# Error
	$error ||= 'Unknown error, probably harmless.';

	# No event
	warn "Unhandled event error: $error" and return unless $event;

	# Error callback
	$self->_run_event('error', $event, $id, $error);
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

# Failed callbacks should not kill everything
sub _run_callback {
	my $self  = shift;
	my $event = shift;
	my $cb    = shift;

	# Invoke callback
	my $value = eval { $self->$cb(@_) };

	# Callback error
	warn qq/Callback "$event" failed: $@/ if $@;

	return $value;
}

sub _tls_accept {
	my ($self, $id) = @_;

	# Connection
	my $c = $self->{_cs}->{$id};

	# Accepted
	if ($c->{handle}->accept_SSL) {

		# Cleanup
		delete $c->{tls_accept};

		# Accept callback
		my $cb = $c->{on_accept};
		$self->_run_event('accept', $cb, $id) if $cb;

		return;
	}

	# Handle error
	$self->_tls_error($id);
}

1;
