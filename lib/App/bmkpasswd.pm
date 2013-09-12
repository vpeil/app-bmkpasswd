package App::bmkpasswd;
use strictures 1;
use Carp;
use Try::Tiny;

use Crypt::Eksblowfish::Bcrypt qw/
  bcrypt 
  en_base64
/;

use parent 'Exporter::Tiny';
our @EXPORT_OK = qw/
  mkpasswd
  passwdcmp
/;

use Bytes::Random::Secure;
my ($brs, $brsnb);
my $getbrs = sub {
  my ($strong) = @_;
  if ($strong) {
    return 
      $brs ||= Bytes::Random::Secure->new(
        Bits => 128,
      )
  }
  return
    $brsnb ||= Bytes::Random::Secure->new(
      Bits        => 128,
      NonBlocking => 1,
    )
};

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
  my $type = "sha$rate";
  return $_can_haz{$type} if defined $_can_haz{$type};

  ## determine (the slow way) if SHA256/512 are available
  ## requires glibc2.7+ or Crypt::Passwd::XS
  my %tests = (
    sha256 => sub {
      my $testc;
      try { $testc = crypt('a', '$5$abc$') }
        catch { warn $_ };
      return unless $testc and index($testc, '$5$abc$') == 0;
      1
    },

    sha512 => sub {
      my $testc;
      try { $testc = crypt('b', '$6$abc$') }
        catch { warn $_ };
      return unless $testc and index($testc, '$6$abc$') == 0;
      1
    },
  );

  if (defined $tests{$type} && $tests{$type}->()) {
    return $_can_haz{$type} = 1
  }

  $_can_haz{$type} = 0;
  return
}


sub _saltgen {
  my ($type, $strong) = @_;

  my $rnd = $strong ? $getbrs->(strong => 1) : $getbrs->() ;

  SALT: {
    if ($type eq 'bcrypt') {
      return en_base64( $rnd->bytes(16) );
    }

    if ($type eq 'sha') {
      my $max = en_base64( $rnd->bytes(16) );
      my $initial = substr $max, 0, 8, '';
      ## Drepper recommends random-length salts:
      $initial .= substr $max, 0, 1, '' for  1 .. rand 8;
      return $initial
    }

    if ($type eq 'md5') {
      return en_base64( $rnd->bytes(6) );
    }
  }

  confess "_saltgen fell through, unknown type $type"
}

sub mkpasswd {
  my ($pwd, $type, $cost, $strong) = @_;

  $type = 'bcrypt' unless $type;
  my $salt;

  TYPE: {
    if ($type =~ /^bcrypt$/i) {
      $cost = '08' unless $cost;

      croak 'Work cost factor must be numeric'
        unless $cost =~ /^[0-9]+$/;
      $cost = "0$cost" if length $cost == 1;

      $salt = _saltgen('bcrypt', $strong);
      my $bsettings = join '', '$2a$', $cost, '$', $salt;

      return bcrypt($pwd, $bsettings)
    }

    # SHA requires Crypt::Passwd::XS or glibc2.7+, recent fBSD etc
    if ($type =~ /sha-?512/i) {
      croak 'SHA hash requested but no SHA support available' 
        unless have_sha(512);
      $salt = join '', '$6$', _saltgen('sha', $strong), '$';
      last TYPE
    }

    if ($type =~ /sha(-?256)?/i) {
      croak 'SHA hash requested but no SHA support available' 
        unless have_sha(256);
      $salt = join '', '$5$', _saltgen('sha', $strong), '$';
      last TYPE
    }

    if ($type =~ /^md5$/i) {
      $salt = join '', '$1$', _saltgen('md5', $strong), '$';
      last TYPE
    }

    croak "Unknown type specified: $type"
  }

  return Crypt::Passwd::XS::crypt($pwd, $salt)
    if have_passwd_xs();

  crypt($pwd, $salt)
}

sub _const_t_eq {
  ## Constant time comparison is probably overrated for comparing
  ## hashed passwords ... but hey, why not?
  my ($first, $second) = @_;
  my ($n, $unequal) = 0;
  no warnings 'substr';
  while ($n < length $first) {
    my $schr = substr($second, $n, 1);
    ++$unequal
      if substr($first, $n, 1) ne (defined $schr ? $schr : '');
    ++$n;
  }
  $unequal ? () : 1
}

sub passwdcmp {
  my ($pwd, $crypt) = @_;
  croak 'Expected a password string and hash'
    unless defined $pwd and $crypt;

  carp 'Possibly passed an invalid hash'
    unless index($crypt, '$') == 0;

  if ($crypt =~ /^\$2a\$\d{2}\$/) {
    ## Looks like bcrypt.
    return $crypt if _const_t_eq( $crypt, bcrypt($pwd, $crypt) )
  } else {
    if (have_passwd_xs()) {
      return $crypt
        if _const_t_eq( $crypt, Crypt::Passwd::XS::crypt($pwd, $crypt) )
    } else {
      return $crypt
        if _const_t_eq( $crypt, crypt($pwd, $crypt) )
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

  use App::bmkpasswd 'mkpasswd', 'passwdcmp';
  my $bcrypted = mkpasswd($passwd);
  say 'matched' if passwdcmp($passwd, $bcrypted);

  ## From a shell:

  bmkpasswd --help
  
  # Generate bcrypted passwords
  # Defaults to work cost factor '08':
  bmkpasswd
  bmkpasswd --workcost='06'

  # SHA requires Crypt::Passwd::XS or glibc2.7+
  bmkpasswd --method='sha512'
  
  # Compare a hash:
  bmkpasswd --check=HASH

  # Check hash generation times:
  bmkpasswd --benchmark

=head1 DESCRIPTION

B<App::bmkpasswd> is a simple bcrypt-enabled mkpasswd. 

Helper functions are also exported for use in other applications; see
L</EXPORTED>.
L<Crypt::Bcrypt::Easy> provides an easier bcrypt-specific
programmatic interface for Perl programmers.

See C<bmkpasswd --help> for usage information.

Uses L<Crypt::Eksblowfish::Bcrypt> for bcrypted passwords.

Bcrypt comes with a configurable work-cost factor; that allows hash generation 
to become configurably slower as computers get faster, thereby 
impeding brute-force hash generation attempts.

See L<http://codahale.com/how-to-safely-store-a-password/> for more 
on why you ought to be using bcrypt or similar "adaptive" techniques.

B<SHA-256> and B<SHA-512> are supported if available. You'll need 
either L<Crypt::Passwd::XS> or a system crypt() that can handle SHA, 
such as glibc-2.7+ or modern FreeBSD builds.

Uses L<Bytes::Random::Secure> to generate random salts. For the paranoid,
constant time comparison is used when comparing hashes; strongly-random salts
can also be enabled.

=head1 EXPORTED

L<Crypt::Bcrypt::Easy> provides an easier programmatic interface, if you're
only interested in generating bcrypt passwords.  If you'd like to make use of
other password types, you can use the exported B<mkpasswd> and B<passwdcmp>
functions:

  use App::bmkpasswd 'mkpasswd', 'passwdcmp';
  # Same as:
  use App::bmkpasswd -all;

This module uses L<Exporter::Tiny> to export functions. This provides for
flexible import options. See the L<Exporter::Tiny> docs for details.

=head2 mkpasswd

  ## Generate a bcrypted passwd with work-cost 08:
  $bcrypted = mkpasswd($passwd);

  ## Generate a bcrypted passwd with other work-cost:
  $bcrypted = mkpasswd($passwd, 'bcrypt', '10');

  ## SHA:
  $crypted = mkpasswd($passwd, 'sha256');
  $crypted = mkpasswd($passwd, 'sha512');

  ## Use a strongly-random salt (requires spare entropy):
  $crypted = mkpasswd($passwd, 'bcrypt', '08', 'strong');
  $crypted = mkpasswd($passwd, 'sha512', 0, 'strong');

=head2 passwdcmp

  ## Compare a password against a hash
  ## passwdcmp() will return the hash if it is a match
  if ( passwdcmp($plaintext, $crypted) ) {
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
