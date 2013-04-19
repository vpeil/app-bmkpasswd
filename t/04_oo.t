use Test::More;
use strict; use warnings FATAL => 'all';

BEGIN {
  use_ok( 'Crypt::Bcrypt::Easy' );
}

my $passwd;
ok( $passwd = bcrypt->crypt('cake'), 'default ->crypt() ok' );
ok( 
  bcrypt->compare( text  => 'cake', crypt => $passwd ),
  'default ->compare() ok'
);
ok( 
  !bcrypt->compare( text => 'foo', crypt => $passwd ),
  'negative default ->compare() ok'
);

undef $passwd;

ok( 
  $passwd = bcrypt->crypt( text  => 'pie', cost  => '04' ),
  'tuned cost ->crypt() ok'
);
ok(
  bcrypt->compare( text  => 'pie', crypt => $passwd ),
  'tuned cost ->compare() ok'
);
ok(
  !bcrypt->compare( text => 'foo', crypt => $passwd ),
  'negative tuned ->compare() ok'
);

undef $passwd;

my $bc = new_ok( 'Crypt::Bcrypt::Easy' );
ok( $passwd = $bc->crypt('cake'), 'obj default ->crypt() ok');
ok(
  $bc->compare( text  => 'cake', crypt => $passwd ),
  'obj default ->compare() ok'
);
ok(
  !$bc->compare( text => 'foo', crypt => $passwd ),
  'negative obj default ->compare() ok'
);

undef $passwd;
undef $bc;

$bc = new_ok( 'Crypt::Bcrypt::Easy' => [ cost => 10 ] );
ok( $passwd = $bc->crypt('pie'), 'obj tuned ->crypt() ok' );
ok(
  $bc->compare( text  => 'pie', crypt => $passwd ),
  'obj tuned ->compare() ok'
);
ok(
  !$bc->compare( text => 'foo', crypt => $passwd ),
  'negative obj tuned ->compare() ok'
);

done_testing;
