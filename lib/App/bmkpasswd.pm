package App::bmkpasswd;
our $VERSION = '1.02';

use strictures 1;

use Carp;

use Try::Tiny;

use Crypt::Eksblowfish::Bcrypt qw/bcrypt en_base64/;

require Exporter;
our @ISA = qw/Exporter/;
our @EXPORT_OK = qw/
  mkpasswd
  passwdcmp
/;

our $HAVE_PASSWD_XS;

sub mkpasswd {
  my ($pwd, $type, $cost) = @_;
  
  $type = 'bcrypt' unless $type;
  
  # a default (randomized) salt
  # can be used for md5 or built on for SHA
  my @p = ( 'a' .. 'z', 'A' .. 'Z', 0 .. 9, '.', '/' );
  my $salt = join '', map { $p[rand@p] } 1 .. 8;
  
  TYPE: {
    if ($type =~ /^bcrypt$/i) {
      $cost = '08' unless $cost;
      $cost = '0$cost' if length $cost == 1;
      $salt = en_base64( join '', map { chr int rand 256 } 1 .. 16 );
      my $bsettings = join '', '$2a$', $cost, '$', $salt;
      return bcrypt($pwd, $bsettings)
    }

    # SHA requires Crypt::Passwd::XS or glibc2.7+
    # Not sure of other libcs with support.
    # Ulrich Drepper's been evangelizing a bit . . .
    if ($type =~ /sha-?512/i) {
      croak "SHA hash requested but no SHA support available" 
        unless have_sha(512);
      # SHA has variable length salts (max 16)
      # Drepper claims this can slow down attacks.
      # ...I'm under-convinced, but there you are:
      $salt .= $p[rand@p] for 1 .. rand 8;
      $salt = '$6$'.$salt.'$';
      last TYPE
    }
    
    if ($type =~ /sha(-?256)?/i) {
      croak "SHA hash requested but no SHA support available" 
        unless have_sha(256);
      $salt .= $p[rand@p] for 1 .. rand 8;
      $salt = '$5$'.$salt.'$';
      last TYPE
    }
    
    if ($type =~ /^md5$/i) {
      $salt = '$1$'.$salt.'$';
      last TYPE
    }

    return
  }

  ## have_sha() will set our package HAVE_PASSWD_XS:
  if ($HAVE_PASSWD_XS) {
    ## ...but make sure the user isn't doing something dumb:
    try {
      require Crypt::Passwd::XS
    } catch {
      croak "\$HAVE_PASSWD_XS=1 but Crypt::Passwd::XS is not loadable"
    };

    return Crypt::Passwd::XS::crypt($pwd, $salt)
  }

  return crypt($pwd, $salt)
}

sub passwdcmp {
  my ($pwd, $crypt) = @_;
  return unless defined $pwd and $crypt;
  
  if ($crypt =~ /^\$2a\$\d{2}\$/) {
    return unless $crypt eq bcrypt($pwd, $crypt)
  } else {
    my $really_have_xs;
    try {
      require Crypt::Passwd::XS;
      $really_have_xs = 1
    };

    if ($really_have_xs) {
      return unless $crypt eq Crypt::Passwd::XS::crypt($pwd, $crypt)
    } else {
      return unless $crypt eq crypt($pwd, $crypt)
    }
  }

  return $crypt  
}

sub have_sha {
  my ($rate) = @_;
  $rate = 512 unless $rate;
  ## determine (the slow way) if SHA256/512 are available
  ## requires glibc2.7+ or Crypt::Passwd::XS

  ## if we have Crypt::Passwd::XS, just use that:
  $HAVE_PASSWD_XS = 0;
  try {
    require Crypt::Passwd::XS;
    $HAVE_PASSWD_XS = 1
  };
  
  return 1 if $HAVE_PASSWD_XS;
  
  ## otherwise, find out the slow way:
  my %tests = (
    256 => sub {
      my $testcrypt = crypt('a', '$5$abc$');
      return unless index($testcrypt, '$5$abc$') == 0;
      return 1
    },
  
    512 => sub {
      my $testcrypt = crypt('b', '$6$abc$');
      return unless index($testcrypt, '$6$abc$') == 0;
      return 1
    },
  );
  
  return unless defined $tests{$rate} and $tests{$rate}->();
  return 1
}

1;
__END__

=pod

=head1 NAME

App::bmkpasswd - bcrypt-capable mkpasswd(1) and exported helpers

=head1 SYNOPSIS

  bmkpasswd --help
  
  ## Generate bcrypted passwords
  ## Defaults to work cost factor '08':
  bmkpasswd
  bmkpasswd --workcost='06'

  ## Use other methods:
  bmkpasswd --method='md5'
  # SHA requires Crypt::Passwd::XS or glibc2.7+
  bmkpasswd --method='sha512'
  
  ## Compare a hash:
  bmkpasswd --check=HASH

=head1 DESCRIPTION

B<App::bmkpasswd> is a simple bcrypt-enabled mkpasswd. (Helper functions 
are also exported for use in other applications; see L</EXPORTED>.)

See C<bmkpasswd --help> for usage information.

Uses L<Crypt::Eksblowfish::Bcrypt> for bcrypted passwords. 
(See L<http://codahale.com/how-to-safely-store-a-password/> for why you 
ought to be using bcrypt or similar "adaptive" techniques).

B<SHA-256> and B<SHA-512> are supported if available. You'll need 
either L<Crypt::Passwd::XS> or a system crypt() that can handle SHA, 
such as glibc-2.7+ or newer FreeBSD builds.

B<MD5> uses the system's crypt() -- support for it is fairly 
universal, but it is known insecure and there is really no valid excuse 
to be using it ;-)

Salts are randomly generated.

=head1 EXPORTED

You can use the exported B<mkpasswd> and B<passwdcmp> functions in 
other Perl modules/applications:

  use App::bmkpasswd qw/mkpasswd passwdcmp/;
  ## Generate a bcrypted passwd with work-cost 08:
  $bcrypted = mkpasswd($passwd);
  ## Generate a bcrypted passwd with other work-cost:
  $bcrypted = mkpasswd($passwd, 'bcrypt', '06');
  ## SHA:
  $crypted = mkpasswd($passwd, 'sha256');
  $crypted = mkpasswd($passwd, 'sha512');

  ## Compare a password against a hash
  ## passwdcmp() will return the hash if it is a match
  $pwd_matched++ if passwdcmp($passwd, $hash);

=head1 BUGS

There is currently no easy way to pass your own salt; frankly, 
this thing is aimed at some projects of mine where that issue is 
unlikely to come up and randomized is appropriate. If that's a problem, 
patches welcome? ;-)

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
