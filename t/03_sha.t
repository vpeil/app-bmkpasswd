use Test::More tests => 9;
use strict; use warnings;

BEGIN {
  use_ok( 'App::bmkpasswd', qw/mkpasswd passwdcmp/ );
}

SKIP: {
  unless ( App::bmkpasswd::have_sha(256) ) {
    diag("No SHA support found\n",
          "You may want to install Crypt::Passwd::XS");

    skip( "No SHA support", 8 );

  } else {
    diag("Found SHA support");
  }
  
  if ( App::bmkpasswd::have_passwd_xs() ) {
    diag("Using Crypt::Passwd::XS for SHA");
  } else {
    diag("Using system crypt() for SHA");
  }

  my $sha;
  ok( $sha = mkpasswd('snacks', 'sha256'), 'SHA256 crypt()' );
  ok( index($sha, '$5$') == 0, 'Looks like SHA256' );
  ok( passwdcmp('snacks', $sha), 'SHA256 compare' );  
  ok( !passwdcmp('things', $sha), 'SHA256 negative compare' );

  my $sha512;
  ok( $sha512 = mkpasswd('snacks', 'sha512'), 'SHA512 crypt()' );
  ok( index($sha512, '$6$') == 0, 'Looks like SHA512' );
  ok( passwdcmp('snacks', $sha512), 'SHA512 compare' );
  ok( !passwdcmp('things', $sha512), 'SHA512 negative compare' );
}
