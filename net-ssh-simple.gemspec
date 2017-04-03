# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "net/ssh/simple/version"

Gem::Specification.new do |s|
  s.name        = "net-ssh-simple"
  s.version     = Net::SSH::Simple::VERSION
  s.authors     = ["Moe"]
  s.email       = ["moe@busyloop.net"]
  s.homepage    = "https://github.com/busyloop/net-ssh-simple"
  s.description = %q{Net::SSH::Simple is a simple wrapper around Net::SSH and Net::SCP.}
  s.summary     = %q{SSH without the headache}

  s.required_ruby_version = '>= 1.9.2'

  s.add_dependency "net-ssh", "= 4.1.0"
  s.add_dependency "net-scp", "= 1.2.1"
  s.add_dependency "blockenspiel", "= 0.5.0"
  s.add_dependency "hashie", "~> 3.5.5"

  s.add_development_dependency "rake", "~> 10.4.2"
  s.add_development_dependency "rspec", "= 2.14.1"
  s.add_development_dependency "simplecov"
  s.add_development_dependency "yard", "~> 0.8.2"
  s.add_development_dependency "bump"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
