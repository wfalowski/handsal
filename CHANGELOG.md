## [1.0.0](https://github.com/wfalowski/handsal/compare/v0.3.0...v1.0.0) (2026-11-16)

### ⚠ BREAKING CHANGES

* **sdk:** createHandsal and createHandsalClient now throw at
construction for an http issuer, jwksUri or tokenUrl on a non-loopback
host unless allowInsecureHttp is set, and for a jwksUri or tokenUrl on
another host or port than issuer (including an https gateway) unless
allowCrossOrigin is set. A module-scope verifier on http stops the
process at startup instead of answering 401.
Also, issuer, jwksUri and tokenUrl must now parse as absolute http(s)
URLs even when getKey is supplied, and a username or password in any of
them is always rejected.

### Features

* **db:** member status column and active-only tenant access (DEV-593) ([7242fd7](https://github.com/wfalowski/handsal/commit/7242fd7101a4e90fe03167c71d008159eda6c687))
* **sdk:** require https and the issuer origin for SDK URLs (DEV-595) ([9f4092a](https://github.com/wfalowski/handsal/commit/9f4092acd86df472e609c6709fa0a5ba86806d62))

### Bug Fixes

* **api:** cap scopes and task_id on denied token events (DEV-596) ([cc9e36f](https://github.com/wfalowski/handsal/commit/cc9e36f0dad6023b23af99857a04006ca70bd8c5))

## [0.3.0](https://github.com/wfalowski/handsal/compare/v0.2.0...v0.3.0) (2026-11-15)

### Features

* add an optional tokenUrl to createHandsalClient (DEV-591) ([99fa377](https://github.com/wfalowski/handsal/commit/99fa377f1889350e9730a963cd6dbbd716691d72))

## [0.2.0](https://github.com/wfalowski/handsal/compare/v0.1.0...v0.2.0) (2026-11-12)

### Features

* add a client-credentials client to the SDK ([e82a67c](https://github.com/wfalowski/handsal/commit/e82a67c6cacd18858f4d55c9f68332b71ece3d8b))

## [0.1.0](https://github.com/wfalowski/handsal/compare/v0.0.1...v0.1.0) (2026-11-11)

### Features

* rename an application from its page ([3869666](https://github.com/wfalowski/handsal/commit/386966678deb04fb6687da12dbdd2990928d0cb7))

# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut
from [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) on `main`.
