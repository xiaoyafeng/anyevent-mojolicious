#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'AnyEvent::Mojolicious' ) || print "Bail out!
";
}

diag( "Testing AnyEvent::Mojolicious $AnyEvent::Mojolicious::VERSION, Perl $], $^X" );
