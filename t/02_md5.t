use Test::More tests => 3;

BEGIN {
  use_ok( 'App::bmkpasswd' );
}

my $md5;
ok( $md5 = mkpasswd('snacks', 'md5'), 'MD5 crypt()' );
ok( passwdcmp('snacks', $md5), 'MD5 compare' );
