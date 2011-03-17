use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'AnyEvent::Mojolicious',
    AUTHOR              => q{"Brane F. Gracnar" <"bfg@frost.ath.cx">},
    VERSION_FROM        => 'lib/AnyEvent/Mojolicious.pm',
    ABSTRACT_FROM       => 'lib/AnyEvent/Mojolicious.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'AnyEvent'   => 5.3,
        'Mojolicious'=> 1.0,
    },
    test => {TESTS => 't/*.t t/*/*.t'},
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'AnyEvent-Mojolicious-*' },
);
