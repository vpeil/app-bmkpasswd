use Test::More;
use strict; use warnings;

use Test::Cmd;

my $cmd = Test::Cmd->new(
  interpreter => $^X,
  workdir => '',
  prog => 'bin/bmkpasswd',
);

{ $cmd->run(args => '-h');
  is $? >> 8, 0, 'bmkpasswd -h exit 0';
  ok !$cmd->stderr, 'bmkpasswd -h produced no stderr';
  like $cmd->stdout, qr/bmkpasswd/, 'bmkpasswd -h';
}

{ $cmd->run(stdin => 'foo');
  is $? >> 8, 0, 'bmkpasswd (defaults) exit 0';
  like $cmd->stderr, qr/Password/, 'bmkpasswd prompted on stderr';
  my $crypt = $cmd->stdout;
  chomp $crypt;
  cmp_ok length($crypt), '==', 60, 'bcrypt output correct length';
  
  $cmd->run(args => "--check=@{[quotemeta $crypt]} foo");
  is $? >> 8, 0, 'bcrypt password comparison exit 0';
  ok !$cmd->stderr, 'bcrypt password comparison produced no stderr' 
    or diag explain $cmd->stderr;
  cmp_ok $cmd->stdout, 'eq', "Match\n$crypt\n",
    'bcrypt password comparison returned hash';
}

done_testing
