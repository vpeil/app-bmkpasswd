requires "Bytes::Random::Secure" => "0.24";
requires "Carp" => "0";
requires "Crypt::Eksblowfish" => "0.003";
requires "Exporter::Tiny" => "0";
requires "Getopt::Long" => "2.24";
requires "POSIX" => "0";
requires "Pod::Usage" => "1.51";
requires "Time::HiRes" => "0";
requires "Try::Tiny" => "0.12";
requires "strictures" => "1";
recommends "Crypt::Passwd::XS" => "0";
recommends "Math::Random::ISAAC::XS" => "0";

on 'test' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "File::Spec" => "0";
  requires "Test::More" => "0.88";
};

on 'test' => sub {
  recommends "CPAN::Meta" => "2.120900";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
};

on 'develop' => sub {
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::CPAN::Changes" => "0.19";
  requires "Test::More" => "0";
  requires "Test::NoTabs" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
};
