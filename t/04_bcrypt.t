use Test::More tests => 5;

BEGIN {
  use_ok( 'App::bmkpasswd' );
}

my $bc;
ok( $bc = mkpasswd('snacks'), 'Bcrypt crypt()' );
ok( passwdcmp('snacks', $bc), 'Bcrypt compare' );

$bc = undef;
ok( $bc = mkpasswd('snacks', 'bcrypt', '06'), 'Bcrypt tuned workcost' );
ok( passwdcmp('snacks', $bc), 'Bcrypt tuned workcost compare' );
