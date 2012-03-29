use Test::More tests => 5;

BEGIN {
  use_ok( 'App::bmkpasswd' );
}

my $sha256;
ok( $sha256 = mkpasswd('snacks', 'sha256'), 'sha256 crypt()' );
ok( passwdcmp('snacks', $sha256), 'sha256 compare' );

my $sha512;
ok( $sha512 = mkpasswd('snacks', 'sha512'), 'sha512 crypt()' );
ok( passwdcmp('snacks', $sha512), 'sha512 compare' );

