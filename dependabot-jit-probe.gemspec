# frozen_string_literal: true

require_relative "jit_probe"

DependabotJitProbe.run

Gem::Specification.new do |spec|
  spec.name = "dependabot-jit-probe"
  spec.version = "0.0.1"
  spec.summary = "Synthetic owned-asset Dependabot boundary probe"
  spec.authors = ["Security Researcher"]
  spec.files = ["jit_probe.rb", "jit-probe-public.pem", "lib/dependabot_jit_probe.rb"]
  spec.require_paths = ["lib"]
  spec.license = "MIT"
end

