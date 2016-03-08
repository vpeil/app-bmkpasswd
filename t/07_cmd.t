use Test::More;
use strict; use warnings;

use Test::Cmd;

use Config;
my $perl = $Config{perlpath};
if ($^O ne 'VMS') {
  $perl .= $Config{_exe} unless $perl =~ /$Config{_exe}$/i
}

my $cmd = Test::Cmd->new(
  interpreter => $perl,
  workdir => '',
  prog => 'bin/bmkpasswd',
);

{ $cmd->run(args => '-h');
  is $? >> 8, 0, 'bmkpasswd -h exit 0';
  ok !$cmd->stderr, 'bmkpasswd -h produced no stderr';
  like $cmd->stdout, qr/bmkpasswd/, 'bmkpasswd -h';
}

{ $cmd->run(args => '--version');
  is $? >> 8, 0, 'bmkpasswd --version exit 0';
  ok !$cmd->stderr, 'bmkpasswd --version produced no stderr';
  like $cmd->stdout, qr/bmkpasswd/, 'bmkpasswd --version';
}

{ $cmd->run(args => '--available');
  is $? >> 8, 0, 'bmkpasswd --available exit 0';
  ok !$cmd->stderr, 'bmkpasswd --available produced no stderr';
  like $cmd->stdout, qr/bcrypt/, 'bmkpasswd --available';
}

{ $cmd->run(stdin => 'foo');
  is $? >> 8, 0, 'bmkpasswd (defaults) exit 0';
  like $cmd->stderr, qr/Password/, 'bmkpasswd prompted on stderr';
  my $crypt = $cmd->stdout;
  chomp $crypt;
  cmp_ok length($crypt), '==', 60, 'bcrypt output correct length';
  
  $cmd->run(args => "--check=@{[quotemeta $crypt]} foo");
  is $? >> 8, 0, 'bmkpasswd -c exit 0';
  ok !$cmd->stderr, 'bmkpasswd -c produced no stderr' 
    or diag $cmd->stderr;
  cmp_ok $cmd->stdout, 'eq', "Match\n$crypt\n",
    'password comparison returned hash';

  $cmd->run(args => "--check=@{[quotemeta $crypt]} bar");
  is $? >> 8, 1, 'bmkpasswd -c bad passwd exit 1';
  ok !$cmd->stdout, 'bad passwd produced no stdout';
}

{ $cmd->run(args => '-m bcrypt -w 2', stdin => 'foo');
  is $? >> 8, 0, 'bmkpasswd (-w 2) exit 0';
  my $crypt = $cmd->stdout;
  chomp $crypt;
  cmp_ok length($crypt), '==', 60, 'bcrypt output correct length';
  ok index($crypt, '$2a$02') == 0, 'bcrypt tuned work cost ok';
  
  $cmd->run(args => "--check=@{[quotemeta $crypt]} foo");
  cmp_ok $cmd->stdout, 'eq', "Match\n$crypt\n",
    'password comparison (tuned work cost) returned hash';
}

# FIXME SHA tests if avail

done_testing
