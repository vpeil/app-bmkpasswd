package App::bmkpasswd;
use strictures 1;
use Carp;
use Try::Tiny;

use Crypt::Eksblowfish::Bcrypt qw/
  bcrypt 
  en_base64
/;

use Crypt::Random::Seed;
my $crs = Crypt::Random::Seed->new;

use Exporter 'import';
our @EXPORT_OK = qw/
  mkpasswd
  passwdcmp
/;

my %_can_haz;
sub have_passwd_xs {
  unless (defined $_can_haz{passwdxs}) {
    try { require Crypt::Passwd::XS;  $_can_haz{passwdxs} = 1 } 
     catch { $_can_haz{passwdxs} = 0 };
   }
  $_can_haz{passwdxs}
}

sub have_sha {
  ## if we have Crypt::Passwd::XS, just use that:
  return 1 if have_passwd_xs();

  my ($rate) = @_;
  $rate = 512 unless $rate;
  my $type = 'sha' . $rate;
  return $_can_haz{$type} if defined $_can_haz{$type};

  ## determine (the slow way) if SHA256/512 are available
  ## requires glibc2.7+ or Crypt::Passwd::XS
  my %tests = (
    sha256 => sub {
      my $testcrypt = crypt('a', '$5$abc$');
      return unless index($testcrypt, '$5$abc$') == 0;
      1
    },

    sha512 => sub {
      my $testcrypt = crypt('b', '$6$abc$');
      return unless index($testcrypt, '$6$abc$') == 0;
      1
    },
  );

  if (defined $tests{$type} && $tests{$type}->()) {
    return $_can_haz{$type} = 1
  }

  $_can_haz{$type} = 0
}


sub _saltgen {
  my ($type) = @_;

  SALT: {
    if ($type eq 'bcrypt') {
      return en_base64( $crs->random_bytes(16) );
    }

    if ($type eq 'sha') {
      my $max = en_base64( $crs->random_bytes(16) );
      my $initial = substr $max, 0, 8, '';
      $initial .= substr $max, 0, 1, '' for  1 .. rand 8;
      return $initial
    }

    if ($type eq 'md5') {
      return en_base64( $crs->random_bytes(6) );
    }
  }

  confess "_saltgen fell through, unknown type $type"
}

sub mkpasswd {
  my ($pwd, $type, $cost) = @_;

  $type = 'bcrypt' unless $type;
  my $salt;

  TYPE: {
    if ($type =~ /^bcrypt$/i) {
      $cost = '08' unless $cost;

      croak "Work cost factor must be numeric"
        unless $cost =~ /^[0-9]+$/;
      $cost = '0$cost' if length $cost == 1;

      $salt = _saltgen('bcrypt');
      my $bsettings = join '', '$2a$', $cost, '$', $salt;

      return bcrypt($pwd, $bsettings)
    }

    # SHA requires Crypt::Passwd::XS or glibc2.7+, recent fBSD etc
    if ($type =~ /sha-?512/i) {
      croak "SHA hash requested but no SHA support available" 
        unless have_sha(512);
      $salt = join '', '$6$', _saltgen('sha'), '$';
      last TYPE
    }

    if ($type =~ /sha(-?256)?/i) {
      croak "SHA hash requested but no SHA support available" 
        unless have_sha(256);
      $salt = join '', '$5$', _saltgen('sha'), '$';
      last TYPE
    }

    if ($type =~ /^md5$/i) {
      $salt = join '', '$1$', _saltgen('md5'), '$';
      last TYPE
    }

    croak "Unknown type specified: $type"
  }

  return Crypt::Passwd::XS::crypt($pwd, $salt)
    if have_passwd_xs();

  return crypt($pwd, $salt)
}

sub passwdcmp {
  my ($pwd, $crypt) = @_;
  return unless defined $pwd and $crypt;

  if ($crypt =~ /^\$2a\$\d{2}\$/) {
    ## Looks like bcrypt.
    return $crypt if $crypt eq bcrypt($pwd, $crypt)
  } else {

    if ( have_passwd_xs() ) {
      return $crypt
        if $crypt eq Crypt::Passwd::XS::crypt($pwd, $crypt)
    } else {
      return $crypt
        if $crypt eq crypt($pwd, $crypt)
    }

  }

  return
}

1;
__END__

=pod

=head1 NAME

App::bmkpasswd - bcrypt-capable mkpasswd(1) and exported helpers

=head1 SYNOPSIS

  ## From Perl:
  use App::bmkpasswd 'mkpasswd';
  my $bcrypted = mkpasswd($passwd);

  ## From a shell:
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

  ## Check hash generation times:
  bmkpasswd --benchmark

=head1 DESCRIPTION

B<App::bmkpasswd> is a simple bcrypt-enabled mkpasswd. (Helper functions 
are also exported for use in other applications; see L</EXPORTED>.)

See C<bmkpasswd --help> for usage information.

Uses L<Crypt::Random::Seed> to generate random salts.
This means that systems with low entropy may block on B<mkpasswd> 
(try L<http://www.issihosts.com/haveged/>).

Uses L<Crypt::Eksblowfish::Bcrypt> for bcrypted passwords. Bcrypt hashes 
come with a configurable work-cost factor; that allows hash generation 
to become configurably slower as computers get faster, thereby 
impeding brute-force hash generation attempts.

See L<http://codahale.com/how-to-safely-store-a-password/> for more 
on why you ought to be using bcrypt or similar "adaptive" techniques.

B<SHA-256> and B<SHA-512> are supported if available. You'll need 
either L<Crypt::Passwd::XS> or a system crypt() that can handle SHA, 
such as glibc-2.7+ or newer FreeBSD builds.

B<MD5> support is fairly universal, but it is known insecure and there 
is really no valid excuse to be using it; it is included here for 
compatibility with ancient hashes.

Salts are randomly generated.

=head1 EXPORTED

You can use the exported B<mkpasswd> and B<passwdcmp> functions in 
other Perl modules/applications:

  use App::bmkpasswd qw/mkpasswd passwdcmp/;

=head2 mkpasswd

  ## Generate a bcrypted passwd with work-cost 08:
  $bcrypted = mkpasswd($passwd);

  ## Generate a bcrypted passwd with other work-cost:
  $bcrypted = mkpasswd($passwd, 'bcrypt', '06');

  ## SHA:
  $crypted = mkpasswd($passwd, 'sha256');
  $crypted = mkpasswd($passwd, 'sha512');

=head2 passwdcmp

  ## Compare a password against a hash
  ## passwdcmp() will return the hash if it is a match
  if ( passwdcmp($passwd, $hash) ) {
    ## Successful match
  } else {
    ## Failed match
  }

=head1 BUGS

There is currently no easy way to pass your own salt; frankly, 
this thing is aimed at some projects of mine where that issue is 
unlikely to come up and randomized is appropriate. If that's a problem, 
patches welcome? ;-)

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=for Pod::Coverage have_(?i:[A-Z_]+)

=cut
