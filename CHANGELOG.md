# Changelog

All notable changes are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/), versions follow
[Semantic Versioning](https://semver.org/).

## [0.8.2] - 2026-10-19

### Changed
- **Card: controls are easier to recognise.** The period selector
  (1 h / 24 h / 7 d / 30 d) is a framed button bar with a calendar icon, the
  selected period is filled in the accent colour. Tabs are larger, the active
  tab is bold, tinted and underlined. Filters (type, direction, severity),
  Apps/Sites/Categories, Volume/Sessions and Inbound/Outbound on the map are
  framed chips with icons – selected chips are filled in their colour with a
  check mark. Hover and keyboard focus are visible.

## [0.8.1] - 2026-10-18

### Fixed
- The country database download could be cut off, leaving the threat map
  without countries for a month. It is now read completely, checked before it
  is used, and an unreadable file triggers a new download.

## [0.8.0] - 2026-10-18

### New
- **Threat map** – new *Map* tab in the card, in the style of Check Point's
  live threat map, but with *your* gateway's data. Toggle between
  - **Inbound**: firewall drops (24 h) and IPS attacks from the internet by
    country, animated arcs to your home location, latest-attacks ticker
  - **Outbound**: your traffic to online services by country (report top sites
    resolved via DNS – CDNs often show the nearest node – plus app-control
    logs as a sample)
- IP → country is looked up **offline** with the free DB-IP Lite Country
  database (CC BY 4.0), downloaded once a month in the background – no IP
  address leaves Home Assistant. Map shapes: Natural Earth (public domain).
- New sensor *Threat map (countries)* (attacking countries in 24 h, data for
  the map as attributes). Requires syslog reception.

## [0.7.0] - 2026-10-18

### New
- **Sensor "Dropped packets"** (OpenTelemetry): packets the gateway dropped
  since start, with the breakdown **by reason** (rulebase, CoreXL, "first packet
  not SYN", …) as attribute; counts per period come from the statistics.
- **Card – Threat Prevention:** detections per day (7 / 30 days, IPS and
  malware stacked), anti-malware status (scanned hosts and unique threats per
  hour / day / week), **firewall drops** per hour and 24 h with top sources and
  services, and dropped packets by reason.
- **Card – System:** new connections per second (tile and chart), connections
  chart, **throughput per interface**, VPN tunnels and the full contract list
  (with expiry dates) to expand.

## [0.6.1] - 2026-10-18

### Fixed
- Sensors for values a report only contains now and then (e.g. IPS events or
  high-risk apps in the hourly report) no longer turn *unavailable* after a
  restart. Once created they stay and show *unknown* until the value is back.
- The gateway's OpenTelemetry *Test Connection* now reports success.

## [0.6.0] - 2026-10-18

### New
- **Dashboard card included – an interactive event viewer.** After installing
  the integration, add the card *Check Point Quantum Spark* from the card
  picker – no extra resources or other custom cards needed. Choose the gateway,
  done.
  - One period selector for everything: **1 h · 24 h · 7 days · 30 days**
  - Summary like the gateway's own report: volume (↓/↑), sessions, IPS,
    malware/DNS blocked, bots, infected – plus top app and top site
  - **Traffic** tab: volume over time (bars with grid), flow diagram
    Download/Upload → categories, top apps / sites / categories by volume or
    sessions with icons, high-risk apps
  - **Threat Prevention** tab: filter by type (IPS, malware/DNS, bots) and
    direction, flow diagram direction → type → action, event list from syslog –
    tap a row for source, target, CVE links and requested URL – and the report
    totals (protections, malware, hosts)
  - **System** tab: blades, internet, VPN, temperatures, memory, eMMC,
    contracts, firmware – plus charts for CPU/DDR temperature and memory over
    the selected period (from the recorder's long-term statistics)
  - Threat events are grouped per alert and host (e.g. "Max Ping Size ×11"),
    with first/last time, targets and single occurrences; filter by severity
  - Brand icons from Simple Icons (bundled, CC0) with Material Design Icons as
    fallback
  - Follows the HA theme (light/dark), English and German, no external requests
- **OpenTelemetry receiver:** the gateway's Skyline/OpenTelemetry export
  (Prometheus remote write) can be sent to `/api/checkpoint_spark/telemetry` –
  basic auth, gateway IP only, size limits, decoded without extra packages
  (snappy block/stream, gzip). New sensors: **CPU load**, **memory load**,
  **booted**, **connections**, **new connections/s**, **WAN download/upload**
  (Mbit/s), **WAN latency / jitter / packet loss**. The card's System tab shows
  them with charts. The gateway's *Test Connection* button (GET /status) is
  answered for the configured gateway. Raw metrics: sensor *Telemetry series*,
  action `checkpoint_spark.telemetry_metrics`.
- **Direction of syslog detections:** every IPS / malware detection now carries
  `direction` – `inbound` (external → internal), `internal` (internal → internal)
  or `outbound` (internal → external). Shown in the card, part of the event data,
  and counted per direction (`ips_by_direction` on *Detections (30 days)*,
  `last_hour_*` / `last_24h_*` on *IPS events (last hour)*). Internal and
  outbound attacks deserve a closer look.

### Changed
- *Booted* no longer flaps by a minute between polls; the card's files are no
  longer cached long-term by browsers (new versions show up after a normal reload)
- Documentation: which syslog settings to use on the gateway
  (system + security logs, UDP, optional "show obfuscated fields")

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
