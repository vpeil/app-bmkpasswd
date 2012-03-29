package App::bmkpasswd;
our $VERSION = '0.01';

use strict;
use warnings;

use Crypt::Eksblowfish::Bcrypt qw/bcrypt en_base64/;

require Exporter;
our @ISA = qw/Exporter/;
our @EXPORT = qw/
  mkpasswd
  passwdcmp
/;


sub passwdcmp {
  my ($pwd, $crypt) = @_;
  return unless defined $pwd and $crypt;
  
  if ($crypt =~ /^\$2a\$\d{2}\$/) {
    return unless $crypt eq bcrypt($pwd, $crypt);
  } else {
    return unless $crypt eq crypt($pwd, $crypt);
  }
  
  return $crypt
}

sub mkpasswd {
  my ($pwd, $type, $cost) = @_;
  
  $type = 'bcrypt' unless $type;
  
  # a default (randomized) salt
  # can be used for md5 or built on for SHA
  my @p = ( 'a' .. 'z', 'A' .. 'Z', 0 .. 9 );
  my $salt = join '', map { $p[rand@p] } 1 .. 8;
  
  TYPE: {
    if ($type =~ /^bcrypt$/i) {
      $cost = '08' unless $cost;
      $cost = '0$cost' if length $cost == 1;
      $salt = en_base64( join '', map { chr int rand 256 } 1 .. 16 );
      my $bsettings = join '', '$2a$', $cost, '$', $salt;
      return bcrypt($pwd, $bsettings);
    }

    ## these are all crypt():

    # SHA requires glibc2.7+
    # Not sure of other libcs with support.
    # Ulrich Drepper's been evangelizing a bit . . .
    if ($type =~ /sha-?512/i) {
      # SHA has variable length salts
      # Drepper claims this can slow down attacks.
      # ...I'm under-convinced, but there you are:
      $salt .= $p[rand@p] for 1 .. rand 8;
      $salt = '$6$'.$salt.'$';
      last TYPE
    }
    
    if ($type =~ /sha(-?256)?/i) {
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
  
  return crypt($pwd, $salt);
}

1;
__END__

=pod

=head1 NAME

App::bmkpasswd - bcrypt-enabled mkpasswd

=head1 SYNOPSIS

  bmkpasswd --help
  
  bmkpasswd
  bmkpasswd --workcost='06'
  
  ## glibc-2.7+ only (that I am aware of):
  bmkpasswd --method='sha512'

=head1 DESCRIPTION

B<App::bmkpasswd> is a simple bcrypt-enabled mkpasswd.

Uses L<Crypt::Eksblowfish::Bcrypt> for bcrypted passwords; all others 
fall back to the system's C<crypt()>.

=head1 EXPORTED

You can use the exported B<mkpasswd> and B<passwdcmp> functions in 
other Perl modules/applications:

  use App::bmkpasswd;
  ## Generate a bcrypted passwd with work-cost 08:
  $bcrypted = mkpasswd($passwd);
  ## Generate a bcrypted passwd with other work-cost:
  $bcrypted = mkpasswd($passwd, 'bcrypt', '06');
  ## SHA:
  $crypted = mkpasswd($passwd, 'sha256');
  $crypted = mkpasswd($passwd, 'sha512');

  ## Compare a password against a hash:
  $pwd_matched++ if passwdcmp($passwd, $hash);

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
