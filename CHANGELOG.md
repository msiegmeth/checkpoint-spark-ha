# Changelog

All notable changes are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/), versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### New
- **Dashboard card included.** After installing the integration, add the card
  *Check Point Quantum Spark* from the card picker – no extra resources or other
  custom cards needed. Choose the gateway, done. Shows status (internet,
  infection, blades, hardware), key figures with detail dialogs, and tabs for
  threats, hosts, apps & sites, real-time detections and system values.
- **Direction of syslog detections:** every IPS / malware detection now carries
  `direction` – `inbound` (external → internal), `internal` (internal → internal)
  or `outbound` (internal → external). Shown in the card, part of the event data,
  and counted per direction (`ips_by_direction` on *Detections (30 days)*,
  `last_hour_*` / `last_24h_*` on *IPS events (last hour)*). Internal and
  outbound attacks deserve a closer look.

## [0.5.2] - 2026-10-18

### Changed
- Maintenance release, no functional changes: the repository now passes the
  HACS validation without exceptions (the integration's own `brand/` folder
  provides the icon), and the developer notes no longer contain
  installation-specific details.

## [0.5.1] - 2026-10-18

### Changed
- "Virus incidents" are now called **"Malware incidents"** – the counter covers
  all malware the anti-virus blade blocks, not only viruses. Entity IDs stay the
  same, so automations and dashboards keep working.

## [0.5.0] - 2026-10-18

### New
- **Syslog via a log server.** Besides receiving directly from the gateway,
  the integration now accepts syslog forwarded by a log server
  (Synology Log Center, rsyslog, syslog-ng, …) – add it under
  *Additional senders*.
- **Forward syslog** to another server (option *Forward syslog to*,
  `host:port`), e.g. to keep a full archive on your NAS while Home Assistant
  evaluates the messages in real time.
- **Detections are stored** (IPS and malware, default 90 days, max 2000) and
  survive restarts. New sensor *Detections (30 days)* with daily counts and
  the last 100 detections; action `checkpoint_spark.detections` returns the
  stored history.
- **Hardening:** rate limit, size limits, bounded buffers, control characters
  stripped, at most 30 events per hour, loop protection for forwarding.
  See [SECURITY.md](SECURITY.md).

## [0.4.0] - 2026-10-18

### New
- **Real-time security logs via syslog** (optional). Point the gateway's syslog
  server to Home Assistant (UDP, default port 5140) and enable *Receive syslog*
  in the options. Only messages from the gateway's IP are accepted.
  - **IPS attacks and malware detections now raise the event
    `checkpoint_spark_threat` within seconds** – with attack name, severity,
    CVE, source, destination and action (`source: syslog`). The same
    attack from the same source is reported at most once per hour.
  - New sensors: *IPS events (last hour)* with the last 20 detections,
    *Firewall drops (last hour)* with top sources and services,
    *Scanned hosts (24 h)* and *Detected threats (24 h)* from the anti-malware
    status, and *Syslog messages* (counter).
  - Option *Ignore sources*: IPs whose detections should not raise events,
    e.g. your own vulnerability scanner.
  - Action `checkpoint_spark.syslog_messages` returns the last raw messages
    (also per product) – handy to analyse further log types.
  - Messages are kept in memory only; nothing is written to disk.

### Upgrade notes
- Syslog is off by default. Port 5514 is often taken (UniFi Network) –
  the default is 5140.

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
