use Test::More;
use strict; use warnings FATAL => 'all';

use App::bmkpasswd -all;

sub get_stderr (&) {
  my $c = shift;

  local *STDERR;
  my $stderr;

  open STDERR, '>', \$stderr or die $!;
  my $res = $c->(@_);
  close STDERR or die $!;

  wantarray ? ($stderr, $res) : $stderr
}


like get_stderr { passwdcmp('foo', 'bar') },
  qr/invalid hash/,
  'invalid hash warns';


done_testing;
