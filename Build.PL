#!/usr/bin/env perl
use strict; 
use warnings;
use Module::Build;

my $build = Module::Build->new(
   module_name   => 'App::bmkpasswd',
   dist_abstract => 'bcrypt-capable mkpasswd(1) and exported helpers',
   dist_author   => 'Jon Portnoy <avenj@cobaltirc.org>',
   license => 'perl',
   
   create_makefile_pl => 'small',
   create_readme => 1,

   configure_requires => {
     'Module::Build' => '0.36',
   },
   
   build_requires => {
     'Test::More'    => 0,
   },
   
   requires => {
     'perl' => '5.8.0',

     'Crypt::Eksblowfish' => '0.003',
     
     'strictures'    => 1,

     'Getopt::Long'  => '2.24',
     'Time::HiRes'   => 0,
     
     'Try::Tiny'     => 0,
     
     'Term::ReadKey' => 0,
   },
   
   recommends => {
     'Crypt::Passwd::XS' => 0,
   },
);

$build->create_build_script;
