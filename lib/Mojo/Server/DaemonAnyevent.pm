package Mojo::Server::DaemonAnyevent;

use strict;
use warnings;

use Scalar::Util qw(weaken);

use AnyEvent::Mojolicious::IOLoop;

use base 'Mojo::Server::Daemon';

=head1 NAME

AnyEvent based version of L<Mojo::Server::Daemon>

=head1 DESCRIPTION

=head1 SYNOPSIS

=head1 METHODS

This class inherits all methods from L<Mojo::Server::Daemon>.

=cut

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	# call parent constructor
	my $self = $class->SUPER::new();

	# manual url handlers
	$self->{_url_handlers} = [];

	bless($self, $class);
	return $self;
}

sub run {
  my $self = shift;

  # Prepare ioloop
  $self->prepare_ioloop;

  # User and group
  $self->setuidgid;

  # no signal handlers will be set
  
  my $l = $self->ioloop;
  
  $l->{_running} = 1;

  # Start loop
  $self->ioloop->start;
}

sub handler_add {
	my ($self, $regex, $cb) = @_;
	return 0 unless (defined $cb && ref($cb) eq 'CODE');
	return 0 unless (defined $regex);
	
	# already compiled regex?
	local $@;
	my $re = (ref($regex) eq 'Regexp') ? $regex : eval { qr/$regex/ };
	# check for injuries..
	return 0 if ($@);
	
	# add handler...
	push(@{$self->{_url_handlers}}, [ $re, $cb ]);
	return 1;
}

sub app_handler {
	my ($self, $class) = @_;
}

sub manual_handler {
	my ($self) = @_;
	$self->on_handler(\ &_default_handler);
}

# default url handler...
sub _default_handler {
	my ($self, $tx) = @_;
	
	# get path
	my $path = $tx->req->url->path->to_string;
	my $cb = $self->_get_handler_cb($path);
	
	if (defined $cb) {
		# invoke handler callback
		weaken $self;
		weaken $tx;
		$cb->($self, $tx);
		return;
	}
	
	# no handler... 404
	$tx->res->code(404);
	$tx->res->headers->content_type('text/plain; charset=utf-8');
	$tx->res->body('No handler defined for: ' . _urldecode($path));
    $tx->resume;
}

# returns handler sub for specified url path
sub _get_handler_cb {
	my ($self, $path) = @_;
	return undef unless (defined $path);
	$path = _urldecode($path);
	
	foreach (@{$self->{_url_handlers}}) {
		if ($path =~ $_->[0]) {
			return $_->[1];
		}
	}
	
	# no handler found!
	return undef;
}

sub _urldecode {
	my ($str) = @_;
	return undef unless (defined $str);
	$str =~ tr/+/ /;
	$str =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
	return $str;	
}

sub _urlencode {
	my ($str) = @_;
	return undef unless (defined $str);
	$str =~ s/([\W])/"%" . uc(sprintf("%2.2x",ord($1)))/eg;
	return $str;
}


=head1 SEE ALSO

=over

=item * L<Mojo::Server::Daemon>

=item * L<Mojo::Server>

=item * L<Mojolicious>

=back

=head1 AUTHOR

Brane F. Gracnar

=cut

1;