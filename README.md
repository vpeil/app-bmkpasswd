# NAME

App::bmkpasswd - bcrypt-capable mkpasswd(1) and exported bcrypt interface

# SYNOPSIS

    ## From Perl:

    use App::bmkpasswd -all;
    my $bcrypted = mkpasswd($passwd);
    say 'matched' if passwdcmp($passwd, $bcrypted);

    my $stronger = mkpasswd($passwd, 'bcrypt', 12);

    ## From a shell:

    bmkpasswd --help

    # Generate bcrypted passwords:
    bmkpasswd

    # Defaults to work cost factor '08':
    bmkpasswd --workcost='06'

    # SHA requires Crypt::Passwd::XS or a recent libc:
    bmkpasswd --method='sha512'

    # Compare a hash:
    bmkpasswd --check=HASH

    # Check hash generation times:
    bmkpasswd --benchmark

# DESCRIPTION

**App::bmkpasswd** is a bcrypt-enabled `mkpasswd` implementation.

Helper functions are also exported for use in other applications; see
["EXPORTED"](#exported) -- however [Crypt::Bcrypt::Easy](https://metacpan.org/pod/Crypt%3A%3ABcrypt%3A%3AEasy) (from this distribution)
provides an easier bcrypt-specific programmatic interface for Perl
programmers.

See `bmkpasswd --help` for command-line usage information.

Bcrypt leverages a work-cost factor allowing hash generation
to become configurably slower as computers get faster, thereby
impeding brute-force hash generation attempts.
See [http://codahale.com/how-to-safely-store-a-password/](http://codahale.com/how-to-safely-store-a-password/) for more
on why you ought to be using bcrypt or similar "adaptive" techniques.

**SHA-256** and **SHA-512** are supported if available. SHA support requires
either [Crypt::Passwd::XS](https://metacpan.org/pod/Crypt%3A%3APasswd%3A%3AXS) or a system crypt() that can handle SHA (such as
glibc-2.7+ or modern FreeBSD builds).

This module uses [Crypt::Eksblowfish::Bcrypt](https://metacpan.org/pod/Crypt%3A%3AEksblowfish%3A%3ABcrypt) as a back-end.

Uses [Bytes::Random::Secure::Tiny](https://metacpan.org/pod/Bytes%3A%3ARandom%3A%3ASecure%3A%3ATiny) to generate random salts. Strongly-random salts
can also be enabled; see ["mkpasswd"](#mkpasswd).

# EXPORTED

[Crypt::Bcrypt::Easy](https://metacpan.org/pod/Crypt%3A%3ABcrypt%3A%3AEasy) provides an easier programmatic interface, but only
generates bcrypt (although it can validate any supported type).  If you would
like to create crypted passwords using other methods, you can use the exported
**mkpasswd** and **passwdcmp** functions:

    # Import selectively:
    use App::bmkpasswd 'mkpasswd', 'passwdcmp';
    # Or import all functions:
    use App::bmkpasswd -all;

This module uses [Exporter::Tiny](https://metacpan.org/pod/Exporter%3A%3ATiny) to export functions. This provides for
flexible import options. See the [Exporter::Tiny](https://metacpan.org/pod/Exporter%3A%3ATiny) docs for details.

## passwdcmp

Compare a password against a hash.

    if ( passwdcmp($plaintext => $crypted) ) {
      ## Successful match
    } else {
      ## Failed match
    }

**passwdcmp** will return the hash if it is a match; otherwise, `undef`
is returned. (This is an API change in `v2.7.1`; prior versions return
an empty list on failure.)

As of `v2.10`, a constant time comparison function is used to compare hashes.

## mkpasswd

    my $crypted = mkpasswd($passwd);
    my $crypted = mkpasswd($passwd, $type);
    my $crypted = mkpasswd($passwd, 'bcrypt', $cost);
    my $crypted = mkpasswd($passwd, $type, $cost, $strongsalt);

    my $crypted = mkpasswd( $passwd =>
      +{
        type    => $type,
        cost    => $cost,
        strong  => $strongsalt,
        saltgen => $saltgenerator,
      }
    );

Generate hashed passwords.

By default, generates a bcrypted passwd with work-cost 08:

    $bcrypted = mkpasswd($passwd);

A different work-cost can be specified for bcrypt passwds:

    $bcrypted = mkpasswd($passwd, 'bcrypt', '10');

SHA-256 and SHA-512 are supported, in which case the work-cost value is ignored:

    $crypted = mkpasswd($passwd, 'sha256');
    $crypted = mkpasswd($passwd, 'sha512');

If a fourth boolean-true argument is specified, a strongly-random salt is
generated. This requires spare entropy, and will block if entropy-starved:

    $crypted = mkpasswd($passwd, 'bcrypt', '08', 'strong');
    $crypted = mkpasswd($passwd, 'sha512', 0, 'strong');

Options can be passed as a HASH, instead. This also lets you pass in a salt
generator coderef:

    $crypted = mkpasswd( $passwd => +{
        type => 'bcrypt',
        cost => '10',
        strong  => 0,
        saltgen => $saltgenerator,
      }
    );

The salt generator is passed the type (one of: `bcrypt`, `sha`, `md5`) and
the value of the **strong** option (default false).

    my $saltgenerator = sub {
      my ($type, $strongsalt) = @_;
      if ($type eq 'bcrypt') {
        # ...
      } elsif ($type eq 'sha') {
        # ...
      } else {
        die "Don't know how to create a salt for type '$type'!"
      }
    };

Most people want random salts, in which case the default salt generator
should be fine.

See ["mkpasswd\_forked"](#mkpasswd_forked) if your application loads this module before forking
or creating threads that generate passwords.

## mkpasswd\_available

    my @available = mkpasswd_available;

    if ( mkpasswd_available('sha512') ) { ... }

Given no arguments, returns the list of available hash types.

Given a type (see ["mkpasswd"](#mkpasswd)), returns boolean true if the method is available. ('bcrypt' is
always available.)

## mkpasswd\_forked

    # After a fork / new thread is created:
    mkpasswd_forked;

To retain secure salts after forking the process or creating a new thread,
it's advisable to either only load this module after creating the new process
or call **mkpasswd\_forked** in the new process to reset the random seeds used
by salt generators.

Added in `v2.6.1`.

# AUTHOR

Jon Portnoy <jon@portnoy.me>

# MAINTAINER

Vitali Peil <vitali.peil@uni-bielefeld.de>

# LICENSE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.
