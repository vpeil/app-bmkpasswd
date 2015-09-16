use Test::More;
use strict; use warnings;

use App::bmkpasswd ();

my $cmp = \&App::bmkpasswd::_eq;
ok  $cmp->('foo', 'foo'), 'foo eq foo';
ok !$cmp->('foo', 'Foo'), 'foo ne Foo';
ok !$cmp->('foo', 'fooo'), 'foo ne fooo';
ok !$cmp->('fooo', 'foo'), 'fooo ne foo';
ok !$cmp->('aaa', 'aaaa'), 'aaa ne aaaa';
ok !$cmp->('', 'abc'), 'empty string ne abc';
ok !$cmp->('abc', ''), 'abc ne empty string';

done_testing
