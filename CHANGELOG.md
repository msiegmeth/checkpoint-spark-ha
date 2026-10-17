# Changelog

All notable changes are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/), versions follow
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-18

### New
- **Gateway health and connectivity** (read-only clish `show` commands):
  CPU and DDR temperature, memory used, eMMC wear, firmware image,
  *Internet* connectivity sensor, *Internet connected since*, public IPv4,
  active VPN tunnels, *Hardware problem* (any voltage / temperature / eMMC
  check not OK) and *Next contract expiry* with the list of expired contracts.
  Serial number and hardware version now show on the device page.
  Only whitelisted fields are kept – the raw outputs contain secrets
  (PPPoE password, setup Wi-Fi password) and are never stored.
- **Actions**
  - `checkpoint_spark.refresh` – fetch all reports now
  - `checkpoint_spark.get_report` – return the last decoded report (for scripts)
  - `checkpoint_spark.show_command` – run a read-only `show …` command and
    return its output (anything else is refused)
- **Option "Redact network data in diagnostics"** – replaces IP and MAC
  addresses and removes gateway name and host, so diagnostics can be shared
  in a public issue. Serial number and public IP are always redacted.
- Automated tests (parsers, report handling, config flow) run on every push.

### Upgrade notes
- Each poll now also runs a few `show` commands (license only every 6 h).
  A read-only administrator is sufficient.

## [0.2.0] - 2026-10-18

### New
- **Threat alerts as events.** The integration now fires the event
  `checkpoint_spark_threat` when something new shows up in the most current
  report: a new malware, a new host with malware incidents, a new *critical*
  IPS protection hit, or a rising number of infected hosts / servers.
  Use it as an automation trigger, e.g. for a push notification.
  The first poll after a restart only sets the baseline, and the same threat is
  reported at most once per 24 hours.
- **Binary sensor "Threat active"** – on while infected hosts, infected servers
  or critically infected hosts are reported.
- **Binary sensor "Blade failure"** – on when one of the monitored software
  blades is not enabled. Pick the blades in the options; on first start the
  currently enabled blades are monitored.
- **Polling interval per report type.** Defaults: hourly 15 min, daily 30 min,
  weekly 3 h, monthly 6 h. This takes load off the gateway.

### Upgrade notes
- The single polling interval option is replaced by one interval per report
  type. Existing settings are taken over (never shorter than the new default).
- Release notes in HACS now come from this changelog.

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
