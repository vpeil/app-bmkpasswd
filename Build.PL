use strict; use warnings;
use Module::Build;

my $build = Module::Build->new(
   module_name   => 'App::bmkpasswd',
   dist_abstract => 'bcrypt-enabled mkpasswd',
   dist_author   => 'Jon Portnoy <avenj@cobaltirc.org>',
   license => 'perl',
   
   create_makefile_pl => 'small',
   create_readme => 1,
   
   build_requires => {
     'Module::Build' => '0.38',
     'Test::More'    => 0,
   },
   
   requires => {
     'perl' => '5.8.0',
     'Getopt::Long'  => 0,
     
     'Crypt::Eksblowfish::Bcrypt' => 0,
     'Term::ReadKey' => 0,
   },
);

$build->create_build_script;
