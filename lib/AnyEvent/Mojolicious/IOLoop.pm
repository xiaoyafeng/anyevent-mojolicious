package AnyEvent::Mojolicious::IOLoop;

use constant DEBUG => $ENV{MOJO_IOLOOP_DEBUG} || 0;

BEGIN {

# is mojo::ioloop already loaded?
  if (_loaded('Mojo::IOLoop')) {
    print STDERR "Unloading real Mojo::IOLoop, installing fake one.\n"
      if DEBUG;
    if (defined $Mojo::IOLoop::LOOP) {
      $Mojo::IOLoop::LOOP->stop();
      undef $Mojo::IOLoop::LOOP;
    }
    _unload('Mojo::IOLoop');
  }
  else {

    # let's just pretend that we are THE Mojo::IOLoop :)
    print STDERR "Acting as the Mojo::IOLoop.\n" if DEBUG;
  }

# we are THE IOLoop :P
  $INC{'Mojo/IOLoop.pm'} = __FILE__;

  sub _unload {

    #my ($self, $class) = @_;
    my $class = shift;

    return unless _loaded($class);

    # Flush inheritance caches
    @{$class . '::ISA'} = ();

    my $symtab = $class . '::';

    # Delete all symbols except other namespaces
    for my $symbol (keys %$symtab) {
      next if $symbol =~ /\A[^:]+::\z/;
      delete $symtab->{$symbol};
    }

    my $inc_file = join('/', split /(?:'|::)/, $class) . '.pm';
    delete $INC{$inc_file};

    return 1;
  }

  sub _loaded {

    #my $class = shift;
    my $name = shift;

    # Handle by far the two most common cases
    # This is very fast and handles 99% of cases.
    return 1 if defined ${"${name}::VERSION"};
    return 1 if defined @{"${name}::ISA"};

    # Are there any symbol table entries other than other namespaces
    foreach (keys %{"${name}::"}) {
      next if substr($_, -2, 2) eq '::';
      return 1 if defined &{"${name}::$_"};
    }

    # No functions, and it doesn't have a version, and isn't anything.
    # As an absolute last resort, check for an entry in %INC
    my $filename = _inc_filename($name);
    return 1 if defined $INC{$filename};

    '';
  }

# Create a INC-specific filename, which always uses '/'
# regardless of platform.
  sub _inc_filename {

#	my $class = shift;
    my $name = shift;    #$class->_class(shift) or return undef;
    join('/', split /(?:\'|::)/, $name) . '.pm';
  }
}

=head1 NAME

AnyEvent::Mojolicious::IOLoop - L<AnyEvent> reimplementation of L<Mojo::IOLoop>.

=head1 DESCRIPTION

TODO

=head1 SYNOPSIS

TODO

=head1 LIMITATIONS

=head1 SEE ALSO

L<Mojo::IOLoop>, L<AnyEvent>, L<EV>

=head1 AUTHOR

Brane F. Gracnar

=cut

package Mojo::IOLoop;

use strict;
use warnings;

use Carp 'carp';


use Carp 'croak';
use File::Spec;
use IO::File;
use Scalar::Util qw(weaken refaddr blessed);

use Socket;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::DNS;

use base 'Mojo::Base';

# Debug
use constant DEBUG => $ENV{MOJO_IOLOOP_DEBUG} || 0;

# TLS support requires IO::Socket::SSL
use constant TLS => $ENV{MOJO_NO_TLS}
  ? 0
  : eval 'use AnyEvent::TLS; 1';

use constant WINDOWS => ($^O =~ m/win/i) ? 1 : 0;

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
__PACKAGE__->attr(
  [qw/on_lock on_unlock/] => sub {
    sub {1}
  }
);
__PACKAGE__->attr(timeout => '0.025');

# Singleton
our $LOOP;

sub DESTROY {
  my $self = shift;

  # drop on_idle
  for my $id (keys %{$self->{_idle}}) { $self->_drop_immediately($id) }

  # drop on_tick
  for my $id (keys %{$self->{_tick}}) { $self->_drop_immediately($id) }
  $self->{_tick_ae} = undef;

  # remove connections and timers
  for my $id (keys %{$self->{_cs}}) { $self->_drop_immediately($id) }

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

  # watchers: listeners, connections, alarms,
  #
  $self->{_cs} = {};

  # number of dns lookups in progress...
  $self->{_dns_loopups} = 0;

  # on_idle callback subs
  $self->{_idle} = {};

  #$self->{_idle_ae} = undef;

  # on_tick callback subs
  $self->{_tick}    = {};
  $self->{_tick_ae} = undef;

  # Ignore PIPE signal
  $SIG{PIPE} = 'IGNORE';
  return $self;
}

sub connect {
  my $self = shift;
  $self = $self->singleton() unless (ref($self));
  my $args = ref $_[0] ? $_[0] : {@_};
  $args->{proto} ||= 'tcp';

  use Data::Dumper;


  if (lc($args->{proto}) ne 'tcp') {
    croak "Unsupported protocol: $args->{proto}";
  }

  print STDERR ref($self), " connect(): args: ", Dumper($args), "\n" if DEBUG;

  my $conn = {g => undef, h => undef};
  my $id = refaddr($conn);
  print STDERR ref($self), " connect(): new connection id: $id\n" if DEBUG;
  $self->{_cs}->{$id} = $conn;

  weaken $self;

  # get handle
  my $handle = delete($args->{handle}) || delete($args->{socket}) || undef;
  $handle = undef unless (defined $handle && fileno($handle) >= 0);
  print STDERR ref($self), " connect(): id $id: handle: $handle\n"
    if DEBUG && $handle;

  # do we have handle?
  if (defined $handle) {
    $self->_handle_connect($id, $handle, $args);
  }
  else {

    # Remove [] from address (ipv6 stuff)
    $args->{address} =~ s/[\[\]]+//g;
    print STDERR ref($self),
      " connect(): id $id: Creating new connection to [$args->{address}]:$args->{port}.\n"
      if DEBUG;
    $conn->{g} = tcp_connect(
      $args->{address},
      $args->{port},

      # on_connect
      sub {
        my ($fh, $host, $port, $retry) = @_;

        # connect failed?
        unless ($fh) {
          print STDERR ref($self), " connect(): id $id: connect failed: $!\n"
            if DEBUG;

#          	print STDERR ref($self), " connect(): id $id: connect failed: $!\n";
          return $self->_error($id, $!);
        }

        print STDERR ref($self),
          " connect(): id $id: connect ok to $host port $port, fh $fh, retry: $retry\n"
          if DEBUG;

        #$conn->{host} = $host;
        #$conn->{port} = $port;
        $self->_handle_connect($id, $fh, $args);
      },

      # on_prepare
      sub {
        my ($fh) = @_;
        print STDERR ref($self), " connect(): id $id: on_prepare, fh $fh\n"
          if DEBUG;
        return $self->connect_timeout();
      }
    );
  }

  return $id;
}

sub connection_timeout {
  my ($self, $id, $timeout) = @_;
  return
    unless (defined $id
    && exists($self->{_cs}->{$id})
    && ref($self->{_cs}->{$id}) eq 'HASH');
  my $c = $self->{_cs}->{$id};

  unless (defined $timeout && $timeout > 0) {
    return $c->{timeout};
  }

  print STDERR ref($self),
    " connection_timeout(): Setting connection timeout $id => $timeout\n"
    if DEBUG;

  # save timeout
  $c->{timeout} = $timeout;

  my $h = $c->{h};
  if (defined $h) {
    $h->timeout($timeout);
  }
}

sub drop {
  my ($self, $id) = @_;
  return unless (defined $id);

  # on_idle callback id?
  if (exists $self->{_idle}->{$id}) {
    print STDERR ref($self), " drop(): Removing on_idle id $id\n" if DEBUG;
    delete($self->{_idle}->{$id});
    return;
  }

  # on_tick callback id?
  if (exists $self->{_tick}->{$id}) {
    print STDERR ref($self), " drop(): Removing on_tick id $id\n" if DEBUG;
    delete($self->{_tick}->{$id});
    return;
  }

  my $c = $self->{_cs}->{$id};
  return unless (defined $id);

  # we want to gracefully drop a connection
  if (ref($c) eq 'HASH' && defined $c->{h}) {
    print STDERR ref($self), " drop(): Will gracefully drop id $id\n"
      if DEBUG;
    weaken $self;
    $c->{h}->on_drain(sub { $self->_drop_immediately($id) });
    return;
  }

  # relentlessly drop this one...
  $self->_drop_immediately($id);
}

sub generate_port {
  my $self = shift;

  # Ports
  my $port = 1 . int(rand 10) . int(rand 10) . int(rand 10) . int(rand 10);
  while ($port++ < 30000) {

    # Try port
    eval { require IO::Socket::INET };
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
  $self = $self->singleton() unless (ref($self));

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
    $addr =~ s/[\[\]]+//g;
    $port = delete($args->{port}) || 3000;
  }
  else {
    $addr = '::';
    $port = delete($args->{port}) || 3000;
  }

  if (DEBUG) {
    no warnings;
    print STDERR ref($self),
      " listen(): id $id will listen on addr = '$addr', port = '$port'\n";
  }

  my $on_accept = delete($args->{on_accept}) || undef;

  #unless (ref($on_accept) eq 'CODE') {
  #  croak "No on_accept defined!";
  #  return;
  #}

  # create tcp server
  $listen->{g} = tcp_server(
    $addr,
    $port,

    # accept cb
    sub {

      # TODO: handle max_accepts!
      my ($fh, $host, $port) = @_;
      print STDERR ref($self),
        " listen() accepted on $id: $fh, $host, $port\n"
        if DEBUG;

      # time to create client handle!
      my $ch = AnyEvent::Handle->new(fh => $fh, no_delay => 1);
      my $cid = refaddr($ch);

      # save handle
      $self->{_cs}->{$cid} = {h => $ch, address => $host, port => $port};

      print STDERR ref($self), " listen(): Created new connection id $cid\n"
        if DEBUG;

      # apply callbacks
      for my $name (qw/error hup read/) {
        my $cb    = $args->{"on_$name"};
        my $event = "on_$name";
        $self->$event($cid => $cb) if $cb;
      }

      # TLS?
      if ($args->{tls}) {
        $ch->on_starttls(
          sub {
            my ($hdl, $ok, $err) = @_;
            unless ($ok) {
              $self->_error($id, $err);
              return;
            }
            if ($on_accept) {
              print STDERR ref($self),
                " listen() id $id: on_starttls $on_accept\n"
                if DEBUG;
              $on_accept->($self, $id);
            }
          }
        );

        # no certificates?
        $args->{tls_cert} = $self->_prepare_cert()
          unless ($args->{tls_cert});
        $args->{tls_key} = $self->_prepare_key()
          unless ($args->{tls_key});

        # get TLS context
        local $@;
        my $ctx = eval { $self->_get_tls_ctx($args) };
        if ($@) {
        	return $self->_error($cid, "Error creating TLS context: $@");
        }

        $ch->starttls('accept', $ctx);

        # fire on_accept handler!
        if ($on_accept) {
          print STDERR ref($self),
            " listen(): firing on_accept callback for id $cid\n"
            if DEBUG;
          $on_accept->($self, $cid);
        }
      }
      else {
        $on_accept->($self, $cid);
      }
    },

    # prepare cb
    sub {
      my ($fh, $host, $port) = @_;
      $self->{_cs}->{$id}->{address} = $host;
      $self->{_cs}->{$id}->{port}    = $port;
    }
  );

  return $id;
}

sub lookup {
  my ($self, $name, $cb) = @_;
  print STDERR ref($self), " lookup(): name '$name', cb: '$cb'\n" if DEBUG;

  # run real resolving method
  weaken $self;
  $self->resolve(
    $name,
    'a_or_aaaa',
    sub {
      my @res = map { $_->[1] } @{$_[1]};
      $cb->($self, @res);
    },
  );
}

sub on_error {
  my ($self, $id, $cb) = @_;
  print STDERR ref($self), " on_error(): id $id => $cb\n" if DEBUG;
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_error cb...
  my $rcb = sub {
    my $err = $_[2] || 'Unknown error.';
    print STDERR ref($self), " on_error(): error on $id: $err\n" if DEBUG;

    # invoke on_error...
    $cb->($self, $id, $err);

    # invoke on_hup, if any...
    if ($c->{on_hup}) {
      print STDERR ref($self), " on_error(): id $id, invoking on_hup\n"
        if DEBUG;
      $c->{on_hup}->();
    }

    # drop handle
    $self->_drop_immediately($id);
  };

  # save it
  $c->{on_error} = $rcb;

  # do we have handle?
  my $h = $c->{h};
  if (defined $h) {
    print STDERR ref($self), " on_error(): id: $id; applying on_error cb.\n"
      if DEBUG;
    $h->on_error($rcb);
  }

  return $self;
}

sub on_hup {
  my ($self, $id, $cb) = @_;

  print STDERR ref($self), " on_hup(): id $id => $cb\n" if DEBUG;
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_error cb...
  my $rcb = sub {
    print STDERR ref($self), " on_hup(): HUP on $id\n" if DEBUG;
    $self->_drop_immediately($id);
    $cb->($self, $id);
  };

  # save it...
  $c->{on_hup} = $rcb;

  # do we have handle?
  my $h = $c->{h};
  if (defined $h) {
    print STDERR ref($self), " on_hup(): id: $id; applying on_hup cb.\n"
      if DEBUG;
    $h->on_timeout($rcb);
    $h->on_eof($rcb);
  }

  return $self;
}

sub on_idle {
  my ($self, $cb) = @_;
  return unless (defined $cb && ref($cb) eq 'CODE');
  print STDERR ref($self), " on_idle: $cb\n" if DEBUG;

  # save callback...
  my $id = refaddr($cb);
  $self->{_idle}->{$id} = $cb;

  $self->_install_on_tick();
  return $id;
}

sub on_read {
  my ($self, $id, $cb) = @_;
  print STDERR ref($self), " on_read(): id $id => $cb\n" if DEBUG;
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_read cb...
  my $rcb = sub {
    if (DEBUG) {
      my $len = length($_[0]->{rbuf});
      print STDERR ref($self),
        " on_read(): id $id: read $len bytes:\n$_[0]->{rbuf}\n";
    }
    my $buf = $_[0]->{rbuf};
    $_[0]->{rbuf} = '';

    print STDERR ref($self), " on_read(): executing cb '$cb'\n" if DEBUG;
    $cb->($self, $id, $buf);
  };

  # save it...
  $c->{on_read} = $rcb;

  # do we have handle?
  my $h = $c->{h};
  if (defined $h) {
    print STDERR ref($self), " on_read(): id: $id; applying on_read cb.\n"
      if DEBUG;
    $h->on_read($rcb);
  }
}

sub on_tick {
  my ($self, $cb) = @_;
  return unless (defined $cb && ref($cb) eq 'CODE');

  # save callback
  my $id = refaddr($cb);
  $self->{_tick}->{$id} = $cb;

  $self->_install_on_tick();

  # timeout?
  my $timeout = $self->timeout();
  return $id unless (defined $timeout && $timeout > 0);

  return $id;
}

sub one_tick {
  my ($self, $timeout) = @_;

  # This is fucking ridiculous...
  # There is no "one_tick" concept in AnyEvent API.

  # well, however, let's just run on_tick
  # on_idle callbacks...
  $self->_do_on_tick();
  $self->_do_on_idle();
}

sub handle {
  my ($self, $id, $raw) = @_;
  $raw = 0 unless (defined $raw);
  return unless my $c = $self->{_cs}->{$id};
  return unless (ref($c) eq 'HASH' && $c->{h});

  my $fh = $c->{h}->fh();
  return $fh if ($raw);
  local $@;
  eval {
    require IO::Socket::INET;
    IO::Socket::INET->new_from_fd(fileno($fh), 'r+');
  };
}

sub local_info {
  my ($self, $id) = @_;
  return {} unless my $c = $self->{_cs}->{$id};
  return {} unless (ref($c) eq 'HASH' && $c->{h});
  my $fh = $c->{h}->fh;
  return {} unless $fh;
  my $sockaddr = getsockname($fh);
  my ($port, $iaddr) = AnyEvent::Socket::unpack_sockaddr($sockaddr);
  my $address = AnyEvent::Socket::ntoa($iaddr);
  return {address => $address, port => $port};
}

sub remote_info {
  my ($self, $id) = @_;
  return {} unless my $c = $self->{_cs}->{$id};
  return {} unless (ref($c) eq 'HASH' && $c->{h});
  my $fh = $c->{h}->fh;
  return {} unless $fh;
  my $sockaddr = getpeername($fh);
  my ($port, $iaddr) = AnyEvent::Socket::unpack_sockaddr($sockaddr);
  my $address = AnyEvent::Socket::ntoa($iaddr);
  return {address => $address, port => $port};
}

sub resolve {
  my ($self, $name, $type, $cb) = @_;
  croak "No query name specified." unless (defined $name && length $name);
  $type = '*' unless (defined $type && length $type);
  $type = lc($type);
  print STDERR ref($self), " resolve(): name: '$name', type: '$type'\n"
    if DEBUG;

  # create resolver
  my $res = AnyEvent::DNS::resolver();
  $res->timeout([$self->dns_timeout()]);

  # increase number of dns lookups
  $self->{_dns_lookups}++;

  # query options
  my %opt = ();
  if ($name eq 'a_or_aaaa') {
    $opt{accept} = ['a', 'aaaa'];
  }
  elsif ($name eq 'cname') {
    $opt{accept} = ['cname'];
  }

  weaken $self;

  # seems like PTR doesn't work
  # well with resolver->resolve($ip, 'ptr');
  if ($type eq 'ptr') {
    AnyEvent::DNS::reverse_lookup $name, sub {
      my $res = [];
      map { push(@{$res}, ['PTR', $_, '3600']) } @_;
      $cb->($self, $res);
    };
    return $self;
  }

  # fire "normal" dns request!
  $res->resolve(
    $name, $type, %opt,
    sub {

      # decrease number of running dns requests...
      $self->{_dns_lookups}-- if ($self->{_dns_lookups});

      my $res = [];
      foreach (@_) {
        my $t = $_->[1];
        my $val_pos = ($type eq 'mx') ? 4 : 3;

        # dns record TTL value
        # Currently there is no option
        # to get TTL data by using AnyEvent::DNS
        my $ttl = 3600;
        my $v   = $_->[$val_pos];

        # mojo tests want uppercase record types...
        push(@{$res}, [uc($t), $v, $ttl]) if (defined $t && defined $v);
      }

      # fire cb
      $cb->($self, $res);
    },
  );

  return $self;
}

sub singleton { $LOOP ||= shift->new(@_) }

sub start {
  my $self = shift;
  $self = $self->singleton() unless (ref($self));

  if ($self->{_running} || $self->{_cv}) {
    print STDERR ref($self),
      " start(): Already running, returning immediately.\n"
      if DEBUG;
    return;
  }

  # we're now running
  $self->{_running} = 1;

  $self->_install_on_tick();

  unless (%{$self->{_cs}}
    || $self->{_dns_lookups}
    || %{$self->{_tick}}
    || %{$self->{_idle}})
  {
    print STDERR ref($self),
      " start(): No handles to watch, returning immediately.\n"
      if DEBUG;
    return;
  }


  $self->_install_on_tick;

  print STDERR ref($self), " start(): Creating condvar\n" if DEBUG;

# create condvar...
# TODO: beware of this monster!
# http://search.cpan.org/~mlehmann/AnyEvent-5.31/lib/AnyEvent/FAQ.pod#Why_do_some_backends_use_a_lot_of_CPU_in_AE::cv->recv?
  $self->{_cv} = AnyEvent->condvar();

  # wait for completion...
  $self->{_cv}->recv();
  undef $self->{_cv};
  $self->{_cv} = undef;

  print STDERR ref($self), " start(): Loop $self stopped!\n" if DEBUG;
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
  print STDERR ref($self), " starttls(): starting TLS on id $id\n" if DEBUG;

  # create TLS ctx
  local $@;
  my $ctx = eval { $self->_get_tls_ctx($args) };
  if ($@) {
    $self->_error($id, 'TLS context creation exception: ' . $@);
    return;
  }

  # start tls...
  $h->starttls('connect', $ctx);

  return $id;
}

sub stop {
  my ($self) = @_;
  $self = $self->singleton() unless (ref($self));
  return unless ($self->{_running} || defined $self->{_cv});

  # delay stopping of LOOP
  $self->{_stop_timer} = AE::timer(
    0.1, 0,
    sub {
      print STDERR ref($self), " stop(): stopping loop $self\n" if DEBUG;
      $self->{_tick_ae} = undef;
      $self->{_cv}->send() if (defined $self->{_cv});

      #$self->{_cv} = undef;
      $self->{_running} = 0;
      delete $self->{_stop_timer};
    }
  );

  $self->{_running} = 0;

}

sub test {
  my ($self, $id) = @_;
  return 1;
  croak 'Method test is not implemented in ' . ref($self);
}

sub timer {
  my ($self, $after, $cb) = @_;
  $self = $self->singleton() unless (ref($self));
  return unless (defined $cb && ref($cb) eq 'CODE');
  weaken $self;
  my $id = undef;

  # create timer...
  my $t = AE::timer(
    $after, 0,
    sub {
      # remove timer
      delete($self->{_id}->{$id});

      # invoke callback...
      $cb->($self);
    }
  );

  # compute real id
  $id = refaddr($t);

  # save it...
  $self->{_cs}->{$id} = $t;
  return $id;
}

sub write {
  my ($self, $id, $chunk, $cb) = @_;
  print STDERR ref($self), " write(): Writing data to id $id, cb='$cb'.\n"
    if DEBUG;
  return unless (exists $self->{_cs}->{$id});
  my $h = $self->{_cs}->{$id}->{h};
  return unless (defined $h);

  print STDERR ref($self), " write(): Writing data to id $id.\n" if DEBUG;


  # add chunk for writing...
  $h->push_write($chunk);

  # write done callback...
  if (ref($cb) eq 'CODE') {
    weaken $self;
    $h->on_drain(
      sub {
        # remove on_drain cb on handle...
        $_[0]->on_drain(undef);

        # run the callback...
        $cb->($self, $id);
      }
    );
  }

  return $self;
}

######################################################
#                 PRIVATE METHODS                    #
######################################################

sub _is_ae {1}

sub _error {
  my ($self, $id, $error) = @_;

  # Connection
  return unless my $c = $self->{_cs}->{$id};

  # Get error callback
  my $cb = $c->{on_error};

  # Cleanup
  $self->_drop_immediately($id);

  # Error
  $error ||= 'Unknown error, probably harmless.';

  # run callback
  $cb->(undef, 1, $error) if ($cb);
  $cb = $c->{on_hup};
  weaken $self;
  $cb->($self, $id) if ($cb);
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

sub _do_on_idle {
  my $self = shift;
  print STDERR ref($self), " _do_on_idle(): Processing on_idle callbacks.\n"
    if DEBUG;

  # run callbacks...
  weaken $self;
  my $i = 0;
  foreach (values %{$self->{_idle}}) { $_->($self); $i++ }
  return $i;
}

sub _do_on_tick {
  my $self = shift;
  print STDERR ref($self), " _do_on_tick(): Processing on_tick callbacks\n"
    if DEBUG;

  # run on_tick callbacks
  weaken $self;
  my $i = 0;
  foreach (values %{$self->{_tick}}) { $_->($self); $i++ }
  return $i;
}

sub _drop_immediately {
  my ($self, $id) = @_;
  return unless defined $id;
  my $c = $self->{_cs}->{$id};
  return 0 unless (defined $id);
  print STDERR ref($self), " _drop_immediately(): Dropping id $id\n" if DEBUG;

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

  # drop everything...
  delete($self->{_cs}->{$id});
}

sub _get_tls_ctx {
  return undef unless (TLS);
  my $self = shift;
  my $args = ref $_[0] ? $_[0] : {@_};

  my %opt = (
    sslv2 => 0,
    sslv3 => 1,
    tlsv1 => 1,
  );

  my $ca = $args->{tls_ca};
  my $ca_is_file = (defined $ca && -T $ca) ? 1 : 0;

  # key/cert
  $opt{key_file}  = $args->{tls_key}  if ($args->{tls_key});
  $opt{cert_file} = $args->{tls_cert} if ($args->{tls_cert});

  my $tls_verify = 0;

  # tls verify cb?
  if ($args->{tls_verify}) {
    $tls_verify = 1;

    if (ref($args->{tls_verify}) eq 'CODE') {
      $opt{verify_cb} = sub {
        my ($tls, $ref, $cn, $depth, $preverify_ok, $x509_store_ctx, $cert) =
          @_;
        print STDERR "VERIFY_CB called\n";

=pod
If you want to verify certificates yourself, you can pass a sub reference along with this parameter to do so. When the callback is called, it will be passed: 
1. a true/false value that indicates what OpenSSL thinks of the certificate,
2. a C-style memory address of the certificate store,
3. a string containing the certificate's issuer attributes and owner attributes, and
4. a string containing any errors encountered (0 if no errors).
5. a C-style memory address of the peer's own certificate (convertible to PEM form with Net::SSLeay::PEM_get_string_X509()).


 The function should return 1 or 0, depending on whether it thinks the certificate is valid or invalid. The default is to let OpenSSL do all of the busy work. 

 The callback will be called for each element in the certificate chain. 
=cut

        # return user-provided callback result
        return $args->{tls_verify}->(
          ($depth) ? $preverify_ok : 0,
          $x509_store_ctx,
          AnyEvent::TLS::certname($cert),
          'Unknown error message.', $cert
        );
        }
    }
  }

  $opt{verify}             = $tls_verify;
  $opt{verify_client_cert} = $tls_verify;
  $opt{verify_peername}    = 'http';
  $opt{ca_file}            = (defined $ca && $ca_is_file) ? $ca : undef;
  $opt{ca_path}            = (defined $ca && $ca_is_file) ? undef : $ca;
  $opt{check_crl} =
    (defined $args->{tls_crl} && -T $args->{tls_crl})
    ? $args->{tls_crl}
    : undef;

  # create TLS context...
  return AnyEvent::TLS->new(%opt);
}

sub _handle_add {
  my ($self, $id, $handle) = @_;
  return unless (defined $id && defined $handle);
  return unless (exists($self->{_cs}->{$id}));
  print STDERR ref($self), " _handle_add(): id $id, handle: $handle\n"
    if DEBUG;
  my $c = $self->{_cs}->{$id};
  $c->{h} = $handle;

  # apply callbacks...
  if (defined $c->{on_error}) {
    print STDERR ref($self),
      " _handle_add(): id $id, setting on_error: $c->{on_error}\n"
      if DEBUG;
    $handle->on_error($c->{on_error});
  }
  if (defined $c->{on_hup}) {
    print STDERR ref($self),
      " _handle_add(): id $id, setting on_hup: $c->{on_hup}\n"
      if DEBUG;
    $handle->on_timeout($c->{on_hup});
    $handle->on_eof($c->{on_hup});
  }
  if (defined $c->{on_read}) {
    print STDERR ref($self),
      " _handle_add(): id $id, setting on_read: $c->{on_read}\n"
      if DEBUG;
    $handle->on_read($c->{on_read});
  }

  # connection timeout...
  my $to = $c->{timeout};
  if (defined $to && $to > 0) {
    print STDERR ref($self),
      " _handle_add(): id $id, setting connection timeout: $to\n"
      if DEBUG;
    $handle->timeout($to);
    $handle->timeout_reset();
  }
}

sub _handle_connect {
  my ($self, $id, $fh, $args) = @_;
  print STDERR ref($self), " _handle_connect(): id $id: fh $fh\n" if DEBUG;

  # register callbacks
  for my $name (qw/error hup read/) {
    my $cb    = $args->{"on_$name"};
    my $event = "on_$name";
    $self->$event($id => $cb) if ($cb);
  }

  # create AnyEvent::Handle
  my $aeh = AnyEvent::Handle->new(fh => $fh);

  #$self->{_cs}->{$id}->{h} = $aeh;
  $self->_handle_add($id, $aeh);

=pod
  $aeh->timeout($self->connection_timeout());

  # register callbacks
  for my $name (qw/error hup read/) {
    my $cb    = $args->{"on_$name"};
    my $event = "on_$name";
    $self->$event($id => $cb);
  }
=cut

  weaken $self;
  my $on_connect = $args->{on_connect};
  $on_connect = undef unless (ref($on_connect) eq 'CODE');

  # TLS?
  if ($args->{tls}) {
    $aeh->on_starttls(
      sub {
        my ($hdl, $ok, $err) = @_;
        unless ($ok) {
          $self->_error($id, $err);
          return;
        }
        if ($on_connect) {
          print STDERR ref($self),
            " _handle_connect() id $id: on_connect starttls $on_connect\n"
            if DEBUG;
          $on_connect->($self, $id);
        }
      }
    );

    # start tls
    $self->start_tls($id, $args);
  }
  else {
    if ($on_connect) {
      print STDERR ref($self),
        " _handle_connect() id $id: on_connect $on_connect\n"
        if DEBUG;
      $on_connect->($self, $id);
    }
  }
}

sub _install_on_tick {
  my ($self) = @_;

  unless (defined $self->{_tick_ae}) {
    return unless (%{$self->{_tick}} || %{$self->{_idle}});
    return unless $self->is_running;

    weaken $self;
    $self->{_tick_ae} = AE::timer(
      0.001,
      $self->timeout(),
      sub {
        my $num_idle = $self->_do_on_idle();
        my $num_tick = $self->_do_on_tick();

        # nothing done? drop on_tick timer
        if ($num_idle == 0 && $num_tick == 0) {
          print STDERR ref($self), " Removing _tick_ae\n" if (DEBUG);
          delete($self->{_tick_ae});
        }
      }
    );
  }
}

1;