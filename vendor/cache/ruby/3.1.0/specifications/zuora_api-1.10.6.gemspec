# -*- encoding: utf-8 -*-
# stub: zuora_api 1.10.6 ruby lib

Gem::Specification.new do |s|
  s.name = "zuora_api".freeze
  s.version = "1.10.6"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Zuora Strategic Solutions Group".freeze]
  s.bindir = "exe".freeze
  s.date = "2022-02-22"
  s.description = "Gem that provides easy integration to Zuora".freeze
  s.email = ["connect@zuora.com".freeze]
  s.homepage = "https://connect.zuora.com".freeze
  s.rubygems_version = "3.3.7".freeze
  s.summary = "Gem that provides easy integration to Zuora".freeze

  s.installed_by_version = "3.3.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4
  end

  if s.respond_to? :add_runtime_dependency then
    s.add_development_dependency(%q<bundler>.freeze, [">= 0"])
    s.add_development_dependency(%q<rake>.freeze, ["~> 10.0"])
    s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0"])
    s.add_development_dependency(%q<rspec_junit_formatter>.freeze, [">= 0"])
    s.add_development_dependency(%q<webmock>.freeze, [">= 0"])
    s.add_development_dependency(%q<simplecov>.freeze, [">= 0"])
    s.add_development_dependency(%q<simplecov-cobertura>.freeze, [">= 0"])
    s.add_runtime_dependency(%q<ougai>.freeze, [">= 0"])
    s.add_runtime_dependency(%q<nokogiri>.freeze, [">= 0"])
    s.add_runtime_dependency(%q<httparty>.freeze, [">= 0"])
    s.add_runtime_dependency(%q<rubyzip>.freeze, [">= 0"])
    s.add_runtime_dependency(%q<railties>.freeze, [">= 4.1.0", "< 6.2"])
  else
    s.add_dependency(%q<bundler>.freeze, [">= 0"])
    s.add_dependency(%q<rake>.freeze, ["~> 10.0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
    s.add_dependency(%q<rspec_junit_formatter>.freeze, [">= 0"])
    s.add_dependency(%q<webmock>.freeze, [">= 0"])
    s.add_dependency(%q<simplecov>.freeze, [">= 0"])
    s.add_dependency(%q<simplecov-cobertura>.freeze, [">= 0"])
    s.add_dependency(%q<ougai>.freeze, [">= 0"])
    s.add_dependency(%q<nokogiri>.freeze, [">= 0"])
    s.add_dependency(%q<httparty>.freeze, [">= 0"])
    s.add_dependency(%q<rubyzip>.freeze, [">= 0"])
    s.add_dependency(%q<railties>.freeze, [">= 4.1.0", "< 6.2"])
  end
end
