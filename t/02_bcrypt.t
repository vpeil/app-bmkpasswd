use Test::More tests => 8;

BEGIN {
  use_ok( 'App::bmkpasswd', qw/mkpasswd passwdcmp/ );
}

my $bc;
ok( $bc = mkpasswd('snacks'), 'Bcrypt crypt()' );
ok( index($bc, '$2a$') == 0, 'Looks like bcrypt' );
ok( passwdcmp('snacks', $bc), 'Bcrypt compare' );
ok( !passwdcmp('things', $bc), 'Bcrypt negative compare' );

$bc = undef;
ok( $bc = mkpasswd('snacks', 'bcrypt', '06'), 'Bcrypt tuned workcost' );
ok( passwdcmp('snacks', $bc), 'Bcrypt tuned workcost compare' );
ok( !passwdcmp('things', $bc), 'Bcrypt tuned negative compare' );
