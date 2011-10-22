require 'bundler/gem_tasks'
require 'bundler/setup'
Bundler::GemHelper.install_tasks
require 'rspec/core/rake_task'

task :default => :test

RSpec::Core::RakeTask.new("test:spec") do |t|
    t.pattern = 'spec/*.rb'
    t.rcov = false
    #t.rspec_opts = '-b -c -f progress'
    t.rspec_opts = '-b -c -f documentation'
end

namespace :test do
  task :coverage do
    require 'cover_me'
    CoverMe.complete!
  end
end

desc 'Run full test suite'
task :test => [ 'test:spec', 'test:coverage' ]


