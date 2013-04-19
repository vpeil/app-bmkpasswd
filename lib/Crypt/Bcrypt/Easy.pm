package Crypt::Bcrypt::Easy;
use Carp;
use strictures 1;
use App::bmkpasswd 'mkpasswd', 'passwdcmp';

use Exporter 'import';
our @EXPORT = 'bcrypt';
sub bcrypt {  Crypt::Bcrypt::Easy->new(@_)  }

=pod

=for Pod::Coverage new

=cut

sub new {
  my ($cls, %params) = @_;
  my $cost = $params{cost} || '08';
  bless \$cost, $cls
}

sub compare {
  my ($self, %params) = @_;

  unless (defined $params{text} && defined $params{crypt}) {
    confess "Expected 'text =>' and 'crypt =>' params"
  }

  passwdcmp($params{text}, $params{crypt})
}

sub crypt {
  my $self = shift;

  my ($text, $cost, $strong);

  if (@_ == 1) {
    $text = $_[0]
  } elsif (@_ > 1) {
    my %params = @_;
    confess "Expected 'text =>' param"
      unless defined $params{text};
    $text = $params{text};
    $cost = $params{cost};
    $strong = $params{strong};
  } else {
    confess "Not enough arguments; expected a password"
  }

  mkpasswd( $text, 'bcrypt', ($cost || $$self), $strong )
}

1;

=pod

=head1 NAME

Crypt::Bcrypt::Easy - Simple bcrypted passwords

=head1 SYNOPSIS

  use Crypt::Bcrypt::Easy;

  my $plain = 'my_password';

  my $passwd = bcrypt->crypt( text => $plain, cost => '08' );

  if (bcrypt->compare( text => $plain, crypt => $passwd )) {
    # Successful match
  }

  # Generate passwords using a different default workcost
  my $bcrypt  = bcrypt( cost => 10 );
  my $crypted = $bcrypt->crypt( $plain );

=head1 DESCRIPTION

This module provides an alternate interface to L<App::bmkpasswd>'s exported
helpers (which were created to power L<bmkpasswd> and are a bit awkward).

This POD briefly covers usage of this interface; 
see L<App::bmkpasswd> for more details.

=head2 bcrypt

  my $bcrypt = bcrypt( cost => '10' );

Creates and returns a new Crypt::Bcrypt::Easy object.

The default workcost is '08'. This can be also be tuned for individual runs;
see L</crypt>.

=head3 crypt

  my $passwd = bcrypt->crypt(
    text   => 'my_password',
    cost   => '08',
    strong => 0,
  );

Or use defaults:

  my $passwd = bcrypt->crypt( 'my_password' );

Create and return a new password hash.

Specifying a boolean true 'strong =>' parameter enables strongly-random salts
(see L<App::bmkpasswd>).

=head3 compare

  if (bcrypt->compare( text => 'my_password', crypt => $passwd)) {
     ...
  }

Returns boolean true if hashes match.
See C<passwdcmp> from L<App::bmkpasswd>.

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
