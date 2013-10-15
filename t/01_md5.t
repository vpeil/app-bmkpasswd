use Test::More tests => 4;
use strict; use warnings;

use App::bmkpasswd -all;

SKIP: {
  unless ( mkpasswd_available('md5') ) {
    diag(
      "crypt() appears to be lacking MD5 support.\n",
      "You may want to install Crypt::Passwd::XS"
    );
    skip( "No MD5 support", 4 );
  }

  my $md5;
  ok( $md5 = mkpasswd('snacks', 'md5'), 'MD5 crypt()' );
  ok( index($md5, '$1$') == 0, 'Looks like MD5' );
  ok( passwdcmp('snacks', $md5), 'MD5 compare' );
  ok( !passwdcmp('things', $md5), 'MD5 negative compare' );
}
