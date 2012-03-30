use Test::More tests => 5;

BEGIN {
  use_ok( 'App::bmkpasswd' );
}

SKIP: {
  skip "No SHA256 support", 2 unless App::bmkpasswd::have_sha(256);
  if ( $App::bmkpasswd::HAVE_PASSWD_XS ) {
    diag("Crypt::Passwd::XS found, using it for SHA256");
  } else {
    diag("Using system crypt()");
  }
  my $sha;
  ok( $sha = mkpasswd('snacks', 'sha256'), 'SHA256 crypt()' );
  ok( passwdcmp('snacks', $sha), 'SHA256 compare' );  
}

SKIP: {
  skip "No SHA512 support", 2 unless App::bmkpasswd::have_sha(512);
  if ( $App::bmkpasswd::HAVE_PASSWD_XS ) {
    diag("Crypt::Passwd::XS found, using it for SHA512");
  } else {
    diag("Using system crypt()");
  }
  my $sha;
  ok( $sha = mkpasswd('snacks', 'sha512'), 'SHA512 crypt()' );
  ok( passwdcmp('snacks', $sha), 'SHA512 compare' );  
}
