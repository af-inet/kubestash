# changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 2.0.2 - 2019-05-11
### Changes
- added support for loading incluster kubernetes config

## 2.0.1 - 2019-03-09
### Changes
- fixed dockerfile
- set default region to 'us-east-1'

## 2.0.0 - 2019-03-09
### Changes
- `-U --uppercase` flag to convert `lower-case` keys in credstash to `LOWER_CASE` secrets
- `pushall` and `daemonall` commands
- various bug fixes
- removed `inject` command

## [1.0.0] - 2018-04-03
### Added
- daemon mode
- `-l --lowercase` flag to enable DNS_SUBDOMAIN key interpolation

### Changed
- keys are no longer converted to DNS_SUBDOMAIN by default
