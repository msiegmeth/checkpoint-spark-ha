# Changelog

All notable changes are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/), versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-17

### Changed
- Newly / critically infected hosts and infected servers are now enabled by default
- Threat Emulation sensors (malware, emulated files) are only enabled by default
  when the Threat Emulation blade is active on the gateway

## [0.1.0] - 2026-10-17

### Added
- Sensors per report type: traffic, download, upload, sessions, high-risk app
  sessions, IPS events, virus / bot / Threat Emulation incidents, infected hosts
  (+ disabled-by-default extras); top lists as unrecorded attributes
- Active blades sensor, firmware version and MAC on the device
- Brand icons (`brand/`, Home Assistant 2026.3+)
- Example dashboard with standard cards, anonymised report sample
- Documentation of the 2FA limitation
- Config flow (host, port, user, password, SSL verification) with login test;
  HTTP 500 `system_error` on login is treated as invalid credentials
- Re-authentication flow
- Options: report types and polling interval
- Timestamp sensor per report type (report generation time)
- Diagnostics with redacted credentials
- English and German translations
