use Test::More;
use strict; use warnings;

use App::bmkpasswd -all;

ok mkpasswd_available('bcrypt'), 'mkpasswd_available ok';

my $bc;
ok( $bc = mkpasswd('snacks'), 'Bcrypt crypt()' );
ok( index($bc, '$2a$') == 0, 'Looks like bcrypt' );
ok( passwdcmp('snacks', $bc), 'Bcrypt compare' );
ok( !passwdcmp('things', $bc), 'Bcrypt negative compare' );

$bc = undef;
ok( $bc = mkpasswd('snacks', 'bcrypt', 2), 'Bcrypt tuned workcost' );
ok( index($bc, '$2a$02') == 0, 'Bcrypt tuned workcost looks ok' );
ok( passwdcmp('snacks', $bc), 'Bcrypt tuned workcost compare' );
ok( !passwdcmp('things', $bc), 'Bcrypt tuned negative compare' );

my $orig_brs = App::bmkpasswd::get_brs;
ok $orig_brs == App::bmkpasswd::get_brs, 'get_brs ok';
mkpasswd_forked;
$bc = mkpasswd('snacks');
ok( index($bc, '$2a$') == 0, 'Bcrypt after mkpasswd_forked ok' );
my $new_brs = App::bmkpasswd::get_brs;
ok $orig_brs != $new_brs, 'mkpasswd_forked reset Bytes::Random::Secure';

done_testing
