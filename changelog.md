# changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `-U --uppercase` flag to convert `lower-case` keys in credstash to `LOWER_CASE` secrets
- `pushall` and `daemonall` commands

## [1.0.0] - 2018-04-03
### Added
- daemon mode
- `-l --lowercase` flag to enable DNS_SUBDOMAIN key interpolation

### Changed
- keys are no longer converted to DNS_SUBDOMAIN by default