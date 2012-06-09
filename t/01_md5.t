use Test::More tests => 5;

BEGIN {
  use_ok( 'App::bmkpasswd', qw/mkpasswd passwdcmp/ );
}

SKIP: {
  my $md5;

  ## Call have_sha to set HAVE_PASSWD_XS
  App::bmkpasswd::have_sha();
  if ( !$App::bmkpasswd::HAVE_PASSWD_XS ) {
    ## Apparently Win32 has a functional crypt() uh, "sometimes"
    unless ( index(mkpasswd('a', 'md5'), '$1$') == 0) {
      diag(
        "crypt() appears to be lacking MD5 support.\n",
        "You may want to install Crypt::Passwd::XS"
      );
      skip( "No MD5 support", 4 );
    }
  }

  ok( $md5 = mkpasswd('snacks', 'md5'), 'MD5 crypt()' );
  ok( index($md5, '$1$') == 0, 'Looks like MD5' );
  ok( passwdcmp('snacks', $md5), 'MD5 compare' );
  ok( !passwdcmp('things', $md5), 'MD5 negative compare' );
}
