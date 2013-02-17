use Test::More;
use strict; use warnings;

use Benchmark 'timethis';

BEGIN {
  diag "This test will need a solid source of entropy; try haveged.";
  use_ok( 'App::bmkpasswd', qw/mkpasswd passwdcmp/ );
}

(sub {
SKIP: {
  App::bmkpasswd::have_passwd_xs();
  if ( ! App::bmkpasswd::have_passwd_xs() ) {
    ## Apparently Win32 has a functional crypt() uh, "sometimes"
    unless ( index(mkpasswd('a', 'md5', 0, 1), '$1$') == 0) {
      skip( "No MD5 support", 4 );
    }
  }

  my $md5;
  ok( $md5 = mkpasswd('snacks', 'md5', 0, 1), 'MD5 crypt()' );
  ok( index($md5, '$1$') == 0, 'Looks like MD5' );
  ok( passwdcmp('snacks', $md5), 'MD5 compare' );
  ok( !passwdcmp('things', $md5), 'MD5 negative compare' );
}

my $bc;
ok( $bc = mkpasswd('snacks', 'bcrypt', '02', 1), 'Bcrypt tuned workcost' );
ok( passwdcmp('snacks', $bc), 'Bcrypt tuned workcost compare' );
ok( !passwdcmp('things', $bc), 'Bcrypt tuned negative compare' );

SKIP: {
  unless ( App::bmkpasswd::have_sha(256) ) {
    skip( "No SHA support", 8 );
  }
  my $sha256;
  ok( $sha256 = mkpasswd('snacks', 'sha256', 0, 1), 'SHA256 crypt()' );
  ok( index($sha256, '$5$') == 0, 'Looks like SHA256' );
  ok( passwdcmp('snacks', $sha256), 'SHA256 compare' );
  ok( !passwdcmp('things', $sha256), 'SHA256 negative compare' );
}
})->() for 1 .. 100;
done_testing;
