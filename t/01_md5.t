use Test::More tests => 5;

BEGIN {
  use_ok( 'App::bmkpasswd', qw/mkpasswd passwdcmp/ );
}

my $md5;
ok( $md5 = mkpasswd('snacks', 'md5'), 'MD5 crypt()' );
ok( index($md5, '$1$') == 0, 'Looks like MD5' );
ok( passwdcmp('snacks', $md5), 'MD5 compare' );
ok( !passwdcmp('things', $md5), 'MD5 negative compare' );
