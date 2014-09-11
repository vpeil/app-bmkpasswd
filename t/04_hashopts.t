use Test::More;
use strict; use warnings FATAL => 'all';

use App::bmkpasswd -all;

my $bc = mkpasswd( snacks => +{
    cost => 6,
  }
);
ok index($bc, '$2a$06') == 0, 'bcrypt looks ok';
ok passwdcmp('snacks', $bc), 'bcrypt compare ok';

SKIP: {
  unless ( mkpasswd_available('sha256') ) {
    skip "No SHA support", 4
  }
  my $sha = mkpasswd( snacks => +{
      type    => 'sha256',
      strong  => 1,
      saltgen => sub {
        my ($type, $strong) = @_;
        ok $strong, 'strong salt opt passed ok';
        ok $type eq 'sha', 'saltgen got correct type';
        return 'ababcdcd'
      },
    }
  );
  ok index($sha, '$5$ababcdcd$') == 0, 'sha with saltgen looks ok';
  ok passwdcmp('snacks', $sha), 'sha with saltgen compares ok';
}

done_testing
