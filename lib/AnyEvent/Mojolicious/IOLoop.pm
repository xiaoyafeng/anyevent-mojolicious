package AnyEvent::Mojolicious::IOLoop;

use constant DEBUG => $ENV{MOJO_IOLOOP_DEBUG} || 0;

BEGIN {

# is mojo::ioloop already loaded?
  if (_loaded('Mojo::IOLoop')) {
    print STDERR "Unloading real Mojo::IOLoop, replacing with our implementation.\n"
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

#  my $class = shift;
    my $name = shift;    #$class->_class(shift) or return undef;
    join('/', split /(?:\'|::)/, $name) . '.pm';
  }
}

our $VERSION = 0.90;

=head1 NAME

AnyEvent::Mojolicious::IOLoop - L<AnyEvent> reimplementation of L<Mojo::IOLoop>.

=head1 DESCRIPTION

AnyEvent::Mojolicious::IOLoop is L<Mojo::IOLoop> implementation on top of excellent
L<AnyEvent>. The idea is to provide fast and feature rich eventloop with lots of modules
to L<Mojolicious> webapps and possibility to run mojo apps inside standalone process.

=head1 WARNING

This module B<UNLOADS> original Mojo::IOLoop class and hijacks it's namespace with
it's own implementation. B<You've been warned.>

=head1 SYNOPSIS

See: L<Mojo::IOLoop/SYNOPSIS>

=head1 PERFORMANCE

Simple benchmark was done using L<ab(8)> with simple L<Mojo::Server::Daemon> with
L<Mojolicious::Lite> hello world application.

B<Application:>

 get '/' => sub {
  my $self = shift;
  $self->render(data => "hello stranger a from " .  $self->tx->remote_address);
 };

B<Test command:>

 /usr/sbin/ab2 -n 20000 -c 100 -k http://127.0.0.1:3000/

Test was performed with L<AnyEvent> version 5.31 powered by L<EV> version 4.03
on Linux i386 (Intel(R) Core2 T9600 2.80GHz) using perl 5.12.1. Mojo stock ioloop was powered by L<IO::Epoll>
version 0.02.

B<Mojo::IOLoop> results:

 Keep-Alive requests:    19212
 Total transferred:      4636287 bytes
 HTML transferred:       620031 bytes
 Requests per second:    846.58 [#/sec] (mean)
 Time per request:       118.123 [ms] (mean)
 Time per request:       1.181 [ms] (mean, across all concurrent requests)
 Transfer rate:          191.65 [Kbytes/sec] received
 
 Connection Times (ms)
              min  mean[+/-sd] median   max
 Connect:        0    0   0.1      0       3
 Processing:     4  114 424.6     29    2606
 Waiting:        4  113 424.7     29    2606
 Total:          4  114 424.6     29    2608
 
 Percentage of the requests served within a certain time (ms)
  50%     29
  66%     30
  75%     31
  80%     31
  90%     32
  95%     35
  98%   2258
  99%   2282
  100%  2608 (longest request)

B<AnyEvent::Mojolicious::IOLoop> results:

 Keep-Alive requests:    19200
 Total transferred:      4454400 bytes
 HTML transferred:       595200 bytes
 Requests per second:    850.63 [#/sec] (mean)
 Time per request:       117.560 [ms] (mean)
 Time per request:       1.176 [ms] (mean, across all concurrent requests)
 Transfer rate:          185.01 [Kbytes/sec] received
 
 Connection Times (ms)
              min  mean[+/-sd] median   max
 Connect:        0    0   0.1      0       3
 Processing:    17  117  10.4    116     246
 Waiting:        0  113  25.0    115     246
 Total:         18  117  10.3    116     246
 
 Percentage of the requests served within a certain time (ms)
  50%    116
  66%    117
  75%    119
  80%    120
  90%    123
  95%    126
  98%    135
  99%    159
  100%   246 (longest request)

So performance is almost the same, except that AnyEvent version of IOLoop
has higher, but also more stable latency under high load.

=head1 LIMITATIONS

=over

=item B<start>

According to IOLoop API L<Mojo::IOLoop/start> method should block if timeout is set to
non-zero value. This is impossible to achieve in running AnyEvent program without
blocking entire process.

Method B<DOESN'T BLOCK> in the following cases:

=over

=item * Loop is already "running" (See L<Mojo::IOLoop/is_running>)

 if ($loop->is_running) {
   $loop->start();  # doesn't block
 }

=item * L<Mojo::IOLoop/timeout> is set to zero value

 $loop->timeout(0);
 $loop->start();  # doesn't block

=item * start method is called with zero argument

 $loop->start(0);  # doesn't block
 
=item * Timeout is set to non-zero value BUT there are no registered I/O handles, timeouts,
dns lookups or connection attempts active in time of start method invocation.

See L<AnyEvent::FAQ>, section "B<Why_do_some_backends_use_a_lot_of_CPU_in_AE::cv-E<gt>recv?>"
for detailed issue description.

 my $loop = Mojo::IOLoop->new();
 $loop->start();  # doesn't block, loop has nothing to do.

=back

=item B<stop>

Method removes B<on_tick and on_idle> invocation timers, but doesn't actually stop
ioloop, becouse there is no way to prevent I/O events to happen
and trigger B<on_read/on_error/on_hup> callbacks without dropping handles. Already registered
timers are also left intact - they will be fired :)

=item B<lookup, resolve>

Async DNS resolver is implemented on top of L<AnyEvent::DNS> module, which doesn't
report dns entry TTL values. B<Returned TTL is always 3600 seconds!>

=item B<connect>

Method L<Mojo::IOLoop/connect> supports only B<tcp> as connection protocol or raw filehandles
using B<handle> argument.

=item B<listen>

Method listen doesn't accept hostnames for B<address> argument, only IPv4 or IPv6
addresses are supported.

Currently unsupported/ignored arguments: B<max_connections, max_accepts>

=item B<on_idle, on_tick>

B<on_tick and on_idle> are emulated using repeating timer
(using L<AE/timer>). AnyEvent doesn't have concept of
ticks in public API, that's why this behaviour must be emulated.

=item B<one_tick>

Method B<one_tick> just runs all B<on_tick> callbacks followed by all B<on_idle> callbacks.
I/O events are handled separately by AnyEvent.

=item B<handle>

Method B<handle> returns raw filehandle if called with second argument.

 my $h = $loop->handle($id);    # returns IO::Socket::INET object reference
 my $fh = $loop->handle($id, 1);  # returns raw filehandle

=back

=head1 SEE ALSO

L<Mojo::IOLoop>, L<AnyEvent>, L<EV>

=head1 AUTHOR

Brane F. Gracnar

=cut

package 
 Mojo::IOLoop;

use strict;
use warnings;

use Carp qw(carp croak);

use File::Spec;
use IO::File;
use Scalar::Util qw(weaken refaddr blessed);

# use Socket;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::DNS;

use base 'Mojo::Base';

our $VERSION = 0.90;

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

  # I/O watchers: listeners, connections, handles
  $self->{_cs} = {};

  # number of dns lookups in progress...
  $self->{_dns_loopups} = 0;

  # on_idle callback subs
  $self->{_idle} = {};

  # on_tick callback subs
  $self->{_tick}    = {};
  $self->{_tick_ae} = undef;
  
  # listeners
  # $self->{_cs} = {};
  
  # timers
  $self->{_timer} = {};

  # Ignore PIPE signal (installed by AnyEvent by default)
  # $SIG{PIPE} = 'IGNORE';

  return $self;
}

sub connect {
  my $self = shift;
  $self = $self->singleton() unless (ref($self));
  my $args = ref $_[0] ? $_[0] : {@_};
  $args->{proto} ||= 'tcp';

  if (lc($args->{proto}) ne 'tcp') {
    croak "Unsupported protocol: $args->{proto}";
  }

  my $conn = {g => undef, h => undef};
  my $id = refaddr($conn);
  my $tls = $args->{tls};
  $self->_dbg(connect => "Connection $id: creating " . (($tls) ? "TLS " : "") . "connection.") if DEBUG;
  $self->{_cs}->{$id} = $conn;

  weaken $self;
  weaken $args;

  # get handle
  my $handle = delete($args->{handle}) || delete($args->{socket}) || undef;
  $handle = undef unless (defined $handle && fileno($handle) >= 0);
  $self->_dbg(connect => "Connection $id: provided handle: $handle.") if DEBUG && $handle;

  # do we have handle?
  if (defined $handle) {
    $self->_handle_connect($id, $handle, $args);
  }
  else {

    # Remove [] from address (ipv6 stuff)
    $args->{address} =~ s/[\[\]]+//g if (defined $args->{address});
    $self->_dbg(connect => "Connection $id: connecting to [$args->{address}]:$args->{port}.") if DEBUG;
    $conn->{g} = tcp_connect(
      $args->{address},
      $args->{port},

      # on_connect
      sub {
        my ($fh, $host, $port, $retry) = @_;

        # connect failed?
        unless ($fh) {
          $self->_dbg(connect => "Connection $id: connect failed: $!") if DEBUG;
          return $self->_error($id, "$!");
        }

        $self->_dbg(connect => "Connection $id: connect succeeded to [$host]:$port, filehandle $fh, retry $retry.") if DEBUG;

        #$conn->{host} = $host;
        #$conn->{port} = $port;
        $self->_handle_connect($id, $fh, $args);
      },

      # on_prepare
      sub {
        my ($fh) = @_;
        if (DEBUG) {
          my $sockaddr = getsockname($fh);
          my ($port, $iaddr) = AnyEvent::Socket::unpack_sockaddr($sockaddr);
          my $address = AnyEvent::Socket::ntoa($iaddr);
          
          $self->_dbg(connect => "Connection $id: connecting from [$address]:$port using socket $fh, connect timeout " . $self->connect_timeout());
        }
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
  
  # save timeout
  $self->_dbg(connection_timeout => "Connection $id: setting connection timeout to $timeout.") if DEBUG;
  $c->{timeout} = $timeout;

  my $h = $c->{h};
  if (defined $h) {
    $self->_dbg(connection_timeout => "Connection $id: applying connection timeout to $timeout.") if DEBUG;
    $h->timeout($timeout);
    $h->timeout_reset();
  }
}

sub drop {
  my ($self, $id) = @_;
  return unless (defined $id);

  # on_idle callback id?
  if (exists $self->{_idle}->{$id}) {
    $self->_dbg(drop => "Removing on_idle callback $id.") if DEBUG;
    delete($self->{_idle}->{$id});
    return;
  }

  # on_tick callback id?
  if (exists $self->{_tick}->{$id}) {
    $self->_dbg(drop => "Removing on_tick callback $id.") if DEBUG;
    delete($self->{_tick}->{$id});
    return;
  }
  
  # timer?
  if (exists($self->{_timer}->{$id})) {
    $self->_dbg(drop => "Removing timer callback $id.") if DEBUG;
    delete($self->{_timer}->{$id});
    return;
  }
  
  my $c = $self->{_cs}->{$id};
  return unless (defined $id);

  # we want to gracefully drop a connection
  if (ref($c) eq 'HASH' && defined $c->{h}) {
    $self->_dbg(drop => "Gracefully removing connection $id.") if DEBUG;
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

sub listen {
  my $self = shift;
  $self = $self->singleton() unless (ref($self));

  # Arguments
  my $args = ref $_[0] ? $_[0] : {@_};

  # TLS check
  croak "AnyEvent::TLS required for TLS support"
    if $args->{tls} && !TLS;

  # no on_accept?
  unless (defined $args->{on_accept} && ref($args->{on_accept}) eq 'CODE') {
    warn "listen(): Undefined on_accept argument.";
    #return;
  }

  # create listener structure...
  my $listen = {g => undef, h => undef};
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
    $self->_dbg(listen => "Listener $id: will listen on addr = '$addr', port = '$port'") if DEBUG;
  }

  # create listener
  $self->_listener_create($id, $args, $addr, $port);
  return $id;
}

sub _listener_create {
  my ($self, $id, $args, $addr, $port) = @_;

  # get listener structure
  my $listen = $self->{_cs}->{$id};
  return unless (defined $listen);
  my $tls = $args->{tls};
  $self->_dbg(
    _listener_create =>
    "Listener $id: creating " . 
    (($tls) ? "TLS " : "") .
    "listener addr = '$addr', port = '$port'"
  ) if DEBUG;

  # TLS listener?
  if ($args->{tls}) {
    # no server certificate/key?
    $args->{tls_cert} = $self->_prepare_cert()
      unless ($args->{tls_cert});
    $args->{tls_key} = $self->_prepare_key()
      unless ($args->{tls_key});
    
    # get TLS context...
    local $@;
    my $tls_ctx = eval { $self->_get_tls_ctx($args) };
    if ($@) {
      $self->_error($id, "Error creating TLS context: $@");
      return;
    }
    
    # save tls stuff
    $listen->{tls_ctx} = $tls_ctx;
    $listen->{tls_cert} = $args->{tls_cert};
    $listen->{tls_key} = $args->{tls_key};
    $listen->{tls_verify} = $args->{tls_verify};
  }
  
  $listen->{on_accept} = $args->{on_accept};
  
  # copy connection callbacks :)
  $listen->{on_error} = $args->{on_error};
  $listen->{on_hup} = $args->{on_hup};
  $listen->{on_read} = $args->{on_read};

  # create tcp server
  local $@;
  $listen->{g} = eval {
    # try to remove socket listener...
    tcp_server(
      $addr,
      $port,

      # accept cb
      sub { $self->_handle_accept($id, $args, @_) },

      # prepare cb
      sub {
        my ($fh, $host, $port) = @_;
        $self->{_cs}->{$id}->{address} = $host;
        $self->{_cs}->{$id}->{port}    = $port;
      }
    );
    
    # make socket world-writeable...
    chmod(oct("0666"), $port);
  };

  # check for tcp_server injuries
  if ($@) {
    croak "Exception while creating listener: $@";
    $self->_error($id);
    return;
  }
}

sub lookup {
  my ($self, $name, $cb) = @_;
  
  $self->_dbg(
    lookup =>
    "Lookup name: '$name', callback: $cb."
  ) if DEBUG;

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
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_error cb...
  my $rcb = sub {
    my $err = $_[2] || 'Unknown error.';
    $self->_dbg(on_error => "Connection $id: ERROR: $err") if DEBUG;

    # invoke on_error...
    $self->_dbg(
         on_error => "Connection $id: firing up on_error callback $cb.") if DEBUG;
    $cb->($self, $id, $err);

    # invoke on_hup, if any...
    if ($c->{on_hup}) {
      $self->_dbg(
         on_error => "Connection $id: firing up on_hup callback $c->{on_hup}.") if DEBUG;
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
    $self->_dbg(
         on_error => "Connection $id: applying on_error callback.") if DEBUG;
    $h->on_error($rcb);
  }

  return $self;
}

sub on_hup {
  my ($self, $id, $cb) = @_;
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_error cb...
  my $rcb = sub {
    $self->_dbg(on_hup => "Connection $id: HUP.") if DEBUG;
    # do we have on_error cb?
    #my $error_cb = $self->{_cs}->{$id}->{on_error};
    #$error_cb->($self, $id, 'HUP') if $error_cb;
    $self->_drop_immediately($id);
    $cb->($self, $id);
  };

  # save it...
  $c->{on_hup} = $rcb;

  # do we have handle?
  my $h = $c->{h};
  if (defined $h) {
    $self->_dbg(on_hup => "Connection $id: applying on_hup callback.") if DEBUG;
    $h->on_timeout($rcb);
    $h->on_eof($rcb);
  }

  return $self;
}

sub on_idle {
  my ($self, $cb) = @_;
  return unless (defined $cb && ref($cb) eq 'CODE');

  # save callback...
  my $id = refaddr($cb);
  $self->{_idle}->{$id} = $cb;
  
  $self->_dbg(
    on_idle =>
    "Created new on_idle event: id $id, callback: $cb."
  ) if DEBUG;

  $self->_install_on_tick();
  return $id;
}

sub on_read {
  my ($self, $id, $cb) = @_;
  return unless (exists $self->{_cs}->{$id});
  my $c = $self->{_cs}->{$id};

  weaken $self;

  # create real on_read cb...
  my $rcb = sub {
    if (DEBUG) {
      my $len = length($_[0]->{rbuf});
      $self->_dbg(
         on_read => "Connection $id: read $len bytes:\n$_[0]->{rbuf}\n");
    }
    my $buf = $_[0]->{rbuf};
    $_[0]->{rbuf} = '';

    $self->_dbg(on_read => "Connection $id: firing up on_read callback.") if DEBUG;
    $cb->($self, $id, $buf);
  };

  # save it...
  $c->{on_read} = $rcb;

  # do we have handle?
  my $h = $c->{h};
  if (defined $h && ! $c->{tls}) {
    $self->_dbg(
         on_read => "Connection $id: applying on_read callback.") if DEBUG;
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
  # and on_idle callbacks...
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
  my $h = eval {
    require IO::Socket::INET;
    IO::Socket::INET->new_from_fd(fileno($fh), 'r+');
  };
  return $h;
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
  
  $self->_dbg(
    resolve =>
    "Resolving name '$name' query type: '$type'."
  ) if DEBUG;

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
  my ($self, $block) = @_;
  $block = 1 unless ($block);
  $self = $self->singleton() unless (ref($self));

  my $ae_model = $AnyEvent::MODEL;
  $self->_dbg(start => "AnyEvent uses '$ae_model' model.") if DEBUG && defined $ae_model;

  if ($self->{_running} || $self->{_cv}) {
    $self->_dbg(start => "Already running, returning immediately.") if DEBUG;
    return;
  }

  # we're now running
  $self->{_running} = 1;
  
  # ioloop timeout == 0?
  my $to = $self->timeout();
  unless (defined $to && $to > 0) {
    $self->_dbg(start => "Zero timeout value, returning immediately.") if DEBUG;
    return;
  }

  # install on_tick and on_idle repeating timers...
  $self->_install_on_tick();

  unless ($block) {
    $self->_dbg(start => "Non-blocking argument given, loop started, returning immediately.");
    return;
  }

  # nothing to watch for?
  unless (%{$self->{_cs}}
    || %{$self->{_cs}}
    || %{$self->{_timer}}
    || $self->{_dns_lookups}
    || %{$self->{_tick}}
    || %{$self->{_idle}})
  {
    $self->_dbg(start => "No handles, connections or timers to watch, returning immediately.") if DEBUG;
    return;
  }

  $self->_dbg(start => "Creating AE condvar, starting IOLoop in blocking mode.") if DEBUG;

# create condvar...
# TODO: beware of this monster!
# http://search.cpan.org/~mlehmann/AnyEvent-5.31/lib/AnyEvent/FAQ.pod#Why_do_some_backends_use_a_lot_of_CPU_in_AE::cv->recv?
  $self->{_cv} = AE::cv();

  # wait for completion...
  $self->{_cv}->recv();
  undef $self->{_cv};
  $self->{_cv} = undef;

  $self->_dbg(start => "IOLoop stopped.") if DEBUG;

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

  # create TLS ctx
  $self->_dbg(start_tls => "Connection $id: Creating TLS context.") if DEBUG;
  local $@;
  my $ctx = eval { $self->_get_tls_ctx($args) };
  if ($@) {
    $self->_error($id, 'TLS context creation exception: ' . $@);
    return;
  }
  
  # on_starttls stuff
  my $on_connect = $self->{_cs}->{$id}->{on_connect};
  $h->on_starttls(
      sub {
        my ($hdl, $ok, $err) = @_;
        # TLS negotiation failed?
        unless ($ok) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation failed: $err") if DEBUG;
          $self->_error($id, $err);
          return;
        }
        # establish on_read callback
        if ($self->{_cs}->{$id}->{on_read}) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation succeeded, applying on_read callback.") if DEBUG;
          $self->{_cs}->{$id}->{h}->on_read($self->{_cs}->{$id}->{on_read});
        }
        
        $self->_dbg(_handle_connect => "Connection $id: TLS negotiation succeeded, applying on_read callback.") if DEBUG;
        if ($on_connect) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation succeeded, firing up on_connect callback.") if DEBUG;
          $on_connect->($self, $id);
        }
      }
  );

  # start tls...
  $self->_dbg(start_tls => "Connection $id: Really starting TLS negotiation on handle.") if DEBUG;
  $h->starttls('connect', $ctx);

  return $id;
}

sub stop {
  my ($self) = @_;
  $self = $self->singleton() unless (ref($self));
  return unless ($self->{_running} || defined $self->{_cv});
  
  # drop on_idle and on_tick timers
  undef $self->{_tick_ae};
  $self->{_tick_ae} = undef;

  # delay stopping of LOOP
  $self->{_stop_timer} = AE::timer(
    0.1, 0,
    sub {
      $self->_dbg(stop => "Stopping IOLoop.") if DEBUG;
      
      $self->{_tick_ae} = undef;
      $self->{_cv}->send() if (defined $self->{_cv});

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
      $self->_dbg(timer => "Timer: $id.") if DEBUG;

      # remove timer
      delete($self->{_timer}->{$id});

      # invoke callback...
      $cb->($self);
    }
  );

  # compute real id
  $id = refaddr($t);

  # save it...
  $self->{_timer}->{$id} = $t;
  return $id;
}

sub write {
  my ($self, $id, $chunk, $cb) = @_;
  if (DEBUG) {
    no warnings;
    my $len = length($chunk);
    $self->_dbg(write => "Writing $len bytes to $id with finalize callback $cb");
  }
  return unless (exists $self->{_cs}->{$id});
  my $h = $self->{_cs}->{$id}->{h};
  return unless (defined $h);

  # add chunk for writing...
  $h->push_write($chunk);

  # write done callback...
  if (ref($cb) eq 'CODE') {
    weaken $self;
    $h->on_drain(
      sub {
        $self->_dbg(write => "Connection $id: write finished. Firing up on_write_finish callback $cb") if DEBUG;

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
  $self->_dbg(_error => "Connection $id: ERROR $error") if DEBUG;

  # Get error callback
  my $err_cb = $c->{on_error};
  my $hup_cb = $c->{on_hup};

  # Cleanup
  $self->_drop_immediately($id);

  # Error
  $error ||= 'Unknown error, probably harmless.';

  # run callbacks
  weaken $self;
  $err_cb->(undef, 1, $error) if ($err_cb);
  $hup_cb->($self, $id) if ($hup_cb);
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
  $self->_dbg(
    _do_on_idle =>
    "Processing on_idle callbacks."
  ) if DEBUG;

  # run callbacks...
  weaken $self;
  my $i = 0;
  foreach (values %{$self->{_idle}}) { $_->($self); $i++ }
  return $i;
}

sub _do_on_tick {
  my $self = shift;
  $self->_dbg(
    _do_on_tick =>
    "Processing on_tick callbacks."
  ) if DEBUG;

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
  #$self->_dbg(_drop_immediately => "TRYYYYY TO DROP connection $id.") if DEBUG;
  return unless (defined $c);
  $self->_dbg(_drop_immediately => "Dropping connection $id.") if DEBUG;

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

  #use Data::Dumper;
  #print "TLS args: ", Dumper($args), "\n";
  my $ca = $args->{tls_ca};
  #print STDERR "CA: '$ca'\n";
  my $ca_is_file = (defined $ca && -T $ca) ? 1 : 0;
  my $ca_is_dir = (defined $ca && -d $ca) ? 1 : 0;
  #print STDERR "CA_IS_FILE: $ca_is_file\n";

  # key/cert
  $opt{key_file}  = $args->{tls_key}  if ($args->{tls_key});
  $opt{cert_file} = $args->{tls_cert} if ($args->{tls_cert});

  my $tls_verify = ($ca_is_file || $ca_is_dir) ? 1 : 0;
  #$tls_verify = 1 if (! $tls_verify && ($args->{tls_key} && $args->{tls_cert}));

  # tls verify cb?
  if ($args->{tls_verify}) {
    $tls_verify = 1;

    if (ref($args->{tls_verify}) eq 'CODE') {
      $self->_dbg(_get_tls_ctx => "We have manual tls_verify callback: $args->{tls_verify}.");
      
      $opt{verify_cb} = sub {
        my ($tls, $ref, $cn, $depth, $preverify_ok, $x509_store_ctx, $cert) =
          @_;
      if (DEBUG) {
        no warnings;
        $self->_dbg(_get_tls_ctx => "TLS verify callback invoked with args: ", join(", ", @_));
      }

# from perldoc IO::Socket::SSL:
#
#If you want to verify certificates yourself, you can pass a sub reference along with this parameter to do so. When the callback is called, it will be passed:
#1. a true/false value that indicates what OpenSSL thinks of the certificate,
#2. a C-style memory address of the certificate store,
#3. a string containing the certificate's issuer attributes and owner attributes, and
#4. a string containing any errors encountered (0 if no errors).
#5. a C-style memory address of the peer's own certificate (convertible to PEM form with Net::SSLeay::PEM_get_string_X509()).
#
#
# The function should return 1 or 0, depending on whether it thinks the certificate is valid or invalid. The default is to let OpenSSL do all of the busy work.
#
# The callback will be called for each element in the certificate chain.

        # AnyEvent::TLS=HASH(0x8787c34), AnyEvent::Handle=HASH(0x8765c74), , 1, 1, -1076548024, 141967304
        # $tls                          $ref,                            $cn, $depth, $preverify_ok, $x509_store_ctx, $cert

        # return user-provided callback result
        my $r = $args->{tls_verify}->(
          ($depth) ? $preverify_ok : 0,
          $x509_store_ctx,
          AnyEvent::TLS::certname($cert),
          'Unknown error message.', $cert
        );
        $r = 0 unless (defined $r);
        
        $self->_dbg(_get_tls_ctx => "TLS verify callback result: $r");# if DEBUG;
        return $r;
        }
    }
  }

  $opt{verify}             = $tls_verify;
  $opt{verify_client_cert} = $tls_verify;
  $opt{verify_require_client_cert} = 1 if $tls_verify;
  $opt{verify_peername}    = 'http';
  if (defined $ca && $ca_is_file) {
    $opt{ca_file} = $ca;
  }
  if (defined $ca && ! $ca_is_file) {
    $opt{ca_path} = $ca;
  }
  #if (defined $args->{tls_crl} && -T $args->{tls_crl}) {
  #  $opt{check_crl} = 1;
  #}
#=pod
#  $opt{check_crl} =
#    (defined $args->{tls_crl} && -T $args->{tls_crl})
#    ? $args->{tls_crl}
#    : undef;
#=cut

  if (DEBUG) {
    use Data::Dumper;
    my $d = Data::Dumper->new([ \ %opt ]);
    #$d->Indent(0);
    #$d->Terse(1);
    $d->Sortkeys(1);
    $self->_dbg(_get_tls_ctx => "TLS context options: " . $d->Dump());
  }

  # create TLS context...
  return AnyEvent::TLS->new(%opt);
}

sub _handle_add {
  my ($self, $id, $handle) = @_;
  return unless (defined $id && defined $handle);
  return unless (exists($self->{_cs}->{$id}));
  $self->_dbg(_handle_add => "Connection $id: registering handle $handle.") if DEBUG;

  my $c = $self->{_cs}->{$id};
  $c->{h} = $handle;

  # apply callbacks...
  if (defined $c->{on_error}) {
    $self->_dbg(_handle_add => "Connection $id: applying on_error callback: $c->{on_error}") if DEBUG;
    $handle->on_error($c->{on_error});
  }
  if (defined $c->{on_hup}) {
    $self->_dbg(_handle_add => "Connection $id: applying on_hup callback: $c->{on_hup}") if DEBUG;
    $handle->on_timeout($c->{on_hup});
    $handle->on_eof($c->{on_hup});
  }
  if (defined $c->{on_read}) {
    $self->_dbg(_handle_add => "Connection $id: applying on_read callback: $c->{on_read}") if DEBUG;
    $handle->on_read($c->{on_read});
  }

  # connection timeout...
  my $to = $c->{timeout};
  if (defined $to && $to > 0) {
    $self->_dbg(_handle_add => "Connection $id: setting connection timeout: $to") if DEBUG;
    $handle->timeout($to);
    $handle->timeout_reset();
  }
}

sub _handle_connect {
  my ($self, $id, $fh, $args) = @_;
  $self->_dbg(_handle_connect => "Connection $id: connect to filehandle $fh.") if DEBUG;

  # create AnyEvent::Handle
  my $aeh = AnyEvent::Handle->new(fh => $fh);

  # add handle...
  $self->_handle_add($id, $aeh);
  
  # TLS?
  $self->{_cs}->{$id}->{tls} = 1 if ($args->{tls});

  # register callbacks
  for my $name (qw/error hup read/) {
    my $cb    = $args->{"on_$name"};
    my $event = "on_$name";
    $self->$event($id => $cb) if ($cb);
  }

  weaken $self;
  my $on_connect = $args->{on_connect};
  $on_connect = undef unless (ref($on_connect) eq 'CODE');

  # TLS?
  if ($args->{tls}) {
    $aeh->on_starttls(
      sub {
        my ($hdl, $ok, $err) = @_;
        # TLS negotiation failed?
        unless ($ok) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation failed: $err") if DEBUG;
          $self->_error($id, $err);
          return;
        }
        # establish on_read callback
        if ($self->{_cs}->{$id}->{on_read}) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation succeeded, applying on_read callback.") if DEBUG;
          $self->{_cs}->{$id}->{h}->on_read($self->{_cs}->{$id}->{on_read});
        }
        
        if ($on_connect) {
          $self->_dbg(_handle_connect => "Connection $id: TLS negotiation succeeded, firing up on_connect callback.") if DEBUG;
          $on_connect->($self, $id);
        }
      }
    );

    # start tls
    $self->_dbg(_handle_connect => "Connection $id: starting TLS negotiation.") if DEBUG;
    local $@;
    my $ctx = eval { $self->_get_tls_ctx($args) };
    if ($@) {
      $self->_error("TLS error: $@");
      return;
    }
    $aeh->starttls('connect', $ctx);
    #$self->start_tls($id, $args);
  }
  else {
    if ($on_connect) {
      $self->_dbg(_handle_connect => "Connection $id: firing up on_connect callback.") if DEBUG;
      $on_connect->($self, $id);
    }
  }
}

sub _dbg {
  return unless DEBUG;
  my ($pkg, $file, $line) = caller();
  my $self = shift;
  my $sub  = shift;
  my $r = refaddr($self);
  print STDERR time(), " ", ref($self), "[$r] $sub (line $line): ", join("", @_), "\n";
}

sub _handle_accept {
  my ($self, $id, $args, $fh, $host, $port) = @_;

  # TODO: handle max_connections
  # TODO: handle max_accepts

  #print STDERR ref($self), " listen() accepted on $id: $fh, $host, $port\n"
  #  if DEBUG;
  #$self->_debug(__LINE__, "listen() id $id accept: $fh, $host, $port");
  $self->_dbg(_handle_accept => "Listener $id: accepted fh: $fh, host: $host, port: $port") if DEBUG;

  my $on_accept = $self->{_cs}->{$id}->{on_accept};
  unless (defined $on_accept && ref($on_accept) eq 'CODE') {
    warn ref($self), " id $id: on_accept is not code reference!";
    $on_accept = undef;
  }

  # time to create client handle!
  my $ch = AnyEvent::Handle->new(fh => $fh, no_delay => 1);
  my $cid = refaddr($ch);

  # save handle
  $self->{_cs}->{$cid} = {h => $ch, address => $host, port => $port};
  
  # mark TLS connection
  $self->{_cs}->{$cid}->{tls} = 1 if ($args->{tls});

  $self->_dbg(_handle_accept => "Created new connection: $cid") if DEBUG;

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
        # TLS handshake failed?
        unless ($ok) {
          $self->_dbg(_handle_accept => "Listener id $id, connection $cid: TLS handshake error: $err") if DEBUG;
          $self->_error($cid, $err);
          return;
        }
        $self->_dbg(_handle_accept => "Connection $cid: successful TLS handshake!") if DEBUG;
        # apply on_read cb (if any)
        if (exists($self->{_cs}->{$cid}->{on_read})) {
          $self->_dbg(_handle_accept => "Connection $cid: Establishing on_read callback after successful TLS handshake") if DEBUG;
          $self->{_cs}->{$cid}->{h}->on_read($self->{_cs}->{$cid}->{on_read});
        }
        if ($on_accept) {
          $self->_dbg(
            _handle_accept =>
            "Listener $id, connection $cid: TLS negotiation succeeded, firing on_accept handler $on_accept.")
          if DEBUG;
          $on_accept->($self, $cid);
        }
      }
    );

    local $@;
    my $ctx = eval { $self->_get_tls_ctx($args) };
    if ($@) {
      $self->_error($id, "Error creating TLS context: $@");
      return;
    }
    unless ($ctx) {
      $self->_dbg(
         _handle_accept =>
         "Listener $id: No TLS context defined on TLS listener! Removing listener.")
      if DEBUG;
      $self->drop($id);
      $self->drop($cid);
      return;
    }

    $self->_dbg(_handle_accept => "Listener $id, connection $cid: starting TLS negotiation.") if DEBUG;
    $ch->starttls('accept', $ctx);
  }
  else {
      $self->_dbg(
        _handle_accept =>
        "Listener $id, connection $cid, firing on_accept handler $on_accept"
      ) if DEBUG;
    $on_accept->($self, $cid);
  }
}


sub _install_on_tick {
  my ($self) = @_;
  
  return if (defined $self->{_tick_ae});
  return unless (%{$self->{_tick}} || %{$self->{_idle}});
  return unless ($self->is_running);

  my $to = $self->timeout();
  return unless (defined $to && $to > 0);

  weaken $self;
  $self->{_tick_ae} = AE::timer(
    0.001, $to,
    sub {
      my $num_idle = $self->_do_on_idle();
      my $num_tick = $self->_do_on_tick();

      # nothing done? drop on_tick timer
      if ($num_idle == 0 && $num_tick == 0) {
        $self->_dbg(
          on_tick =>
          "No on tick or on_idle callbacks defined, removing repeating timer."
        ) if DEBUG;
        delete($self->{_tick_ae});
      }
    }
  );
}

1;
