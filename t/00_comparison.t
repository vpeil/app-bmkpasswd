use Test::More;
use strict; use warnings FATAL => 'all';

use App::bmkpasswd ();

my $cmpr = \&App::bmkpasswd::_const_t_eq;

ok $cmpr->('foo', 'foo');
ok $cmpr->('123foo', '123foo');
ok $cmpr->('$5$foo$things', '$5$foo$things');

ok !$cmpr->('foo', 'FOO');
ok !$cmpr->('foo', 'bar');
ok !$cmpr->('foo', 'fooo');
ok !$cmpr->('foo', 'fo');
ok !$cmpr->('fo', 'foo');
ok !$cmpr->('fooo', 'foo');

done_testing
