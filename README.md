# Check Point Quantum Spark for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz/docs/faq/custom_repositories)
[![Validate](https://github.com/msiegmeth/checkpoint-spark-ha/actions/workflows/validate.yml/badge.svg)](https://github.com/msiegmeth/checkpoint-spark-ha/actions/workflows/validate.yml)
[![GitHub release](https://img.shields.io/github/v/release/msiegmeth/checkpoint-spark-ha)](https://github.com/msiegmeth/checkpoint-spark-ha/releases)

🇩🇪 [Deutsche Version](README.de.md)

Custom integration that reads the **security reports** of a locally managed
**Check Point Quantum Spark** gateway (Gaia Embedded, R81.10.x / R82.00.x)
through its local REST API and exposes the key figures as Home Assistant
sensors.

- Local polling only, no cloud, no external Python requirements
- **Read-only**: the integration only calls `login`, `generate-report`,
  `logout` and clish commands starting with `show`. It never changes the
  gateway configuration.
- Every poll opens a short session and logs out again – no session is kept.

> This is a community project and is not affiliated with or endorsed by
> Check Point Software Technologies Ltd.

## Requirements

- Quantum Spark appliance, **locally managed** (not SMP / cloud managed)
- Firmware R81.10.x or R82.00.x (others may work)
- REST API enabled on the gateway (`set rest-api mode on` in clish)
- A dedicated administrator account, ideally with the **read-only** role
- Administrator **2FA disabled** – the REST API cannot do a second factor
  (see [gateway setup](docs/gateway-setup.md#3-two-factor-authentication-2fa))
- Home Assistant 2025.8 or newer

See [docs/gateway-setup.md](docs/gateway-setup.md) for the gateway side.

## Installation

### HACS (recommended)

[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=msiegmeth&repository=checkpoint-spark-ha&category=integration)

1. Click the button above (or in HACS: ⋮ → **Custom repositories**, repository
   `https://github.com/msiegmeth/checkpoint-spark-ha`, type **Integration**).
2. Click **Download** and confirm.
3. Restart Home Assistant (**Settings → System → ⋮ → Restart**).

New releases are then offered as updates in Home Assistant.

### Manual

1. Download `Source code (zip)` of the latest
   [release](https://github.com/msiegmeth/checkpoint-spark-ha/releases/latest)
   and unpack it.
2. Copy the folder `custom_components/checkpoint_spark` into the
   `custom_components` folder of your Home Assistant configuration
   (create `custom_components` if it does not exist). The result must be
   `<config>/custom_components/checkpoint_spark/manifest.json`.
   Tools: Samba share, SSH / Terminal add-on or the Studio Code Server add-on.
3. Restart Home Assistant.

Manual installations are **not** updated automatically – repeat the steps
for a new release.

## Configuration

[![Open your Home Assistant instance and start setting up Check Point Quantum Spark.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=checkpoint_spark)

Click the button above, or go to **Settings → Devices & services → Add
integration → Check Point Quantum Spark**. If the integration is not in the
list, reload the browser page (the list is cached).

| Field | Default | Description |
|---|---|---|
| Host / IP | – | Address of the gateway, e.g. `192.168.1.1` |
| Port | `4434` | REST API port |
| Username / Password | – | Gateway administrator |
| Verify SSL certificate | off | Spark uses a self-signed certificate by default |

The login is tested during setup. If the password changes later, Home
Assistant asks you to re-authenticate.

### Options

| Option | Default | Range |
|---|---|---|
| Report types | `daily` | any of `hourly`, `daily`, `weekly`, `monthly` (at least one) |
| Polling interval per report type | hourly 15, daily 30, weekly 180, monthly 360 min | 5 – 1440 min |
| Monitored blades | blades enabled at first start | used by the *Blade failure* sensor |
| Redact network data in diagnostics | off | replaces IPs/MACs, removes gateway name and host |

Generating a report costs some CPU on the gateway. Keep the interval
moderate, especially when several report types are selected.

## Entities

All entities belong to one device per gateway. `<type>` is the report type
(`hourly`, `daily`, `weekly`, `monthly`); a report covers the last hour, 24 h,
7 days or 30 days. Sensors are only created for values the report actually
contains (e.g. the hourly report has no IPS or high-risk figures).

| Entity | Unit | Attributes (not recorded) |
|---|---|---|
| `<type>` traffic | GB | `top_apps_by_bandwidth`, `top_sites_by_bandwidth`, `top_categories_by_bandwidth`, `top_users_by_bandwidth`, `bandwidth_history` |
| `<type>` download / upload | GB | – |
| `<type>` sessions | – | `top_apps_by_sessions`, `top_sites_by_sessions`, `top_categories_by_sessions`, `top_users_by_sessions` |
| `<type>` high-risk app sessions | – | `top_high_risk_apps`, `top_high_risk_users` |
| `<type>` IPS events | – | `top_protections` (name, sessions, severity, CVE) |
| `<type>` malware incidents (entity id `…_virus_incidents`) | – | `top_malwares` (name, incidents, severity) |
| `<type>` bot incidents | – | – |
| `<type>` infected hosts | – | `top_infected_hosts`, `infected_hosts`, `possibly_infected_hosts` |
| `<type>` newly / critically infected hosts, infected servers | – | – |
| `<type>` Threat Emulation malware, emulated files | – | enabled by default only if the Threat Emulation blade is active |
| `<type>` report (timestamp, diagnostic) | – | `period_start`, `status`, `fetched` |
| Active blades (diagnostic) | – | `blades` (enabled state per software blade) |

| Threat active (binary, problem) | – | `report_type`, `infected_hosts`, `infected_servers`, `critically_infected_hosts` |
| Blade failure (binary, problem) | – | `monitored`, `disabled` |

**Gateway health** (from read-only clish `show` commands, only created when the firmware supports them):

| Entity | Unit | Attributes |
|---|---|---|
| CPU temperature / DDR temperature | °C | `internal` (CPU) |
| Memory used | MB | – |
| eMMC wear (diagnostic) | % | worst chip, upper bound of the reported range |
| Firmware (diagnostic) | – | current image name |
| Internet (binary, connectivity) | – | `name`, `type`, `interface`, `link_status` |
| Internet connected since (timestamp) | – | same as above |
| Public IPv4 (diagnostic) | – | – |
| VPN tunnels up | – | `tunnels` |
| Hardware problem (binary, problem, diagnostic) | – | `problems` |
| Next contract expiry (timestamp) | – | `contracts` (SKU, expiry, expired), `expired_contracts` |

The device shows the firmware version and MAC address from the report.

## Threat events

The event `checkpoint_spark_threat` is fired when the most current selected
report (hourly → daily → weekly → monthly) contains something new compared
to the previous poll. Event data:

| Field | Content |
|---|---|
| `kind` | `malware`, `host`, `critical_protection`, `infected_hosts`, `infected_servers`, `critically_infected_hosts` |
| `name` | malware / protection name or host IP (for counters: the summary key) |
| `value` | incidents, hits or new counter value (`previous` = old value for counters) |
| `severity`, `cve` | when the report provides them |
| `report_type`, `entry_id` | source |

The first poll after a restart only sets the baseline; the same item is
reported at most once per 24 hours.

```yaml
triggers:
  - trigger: event
    event_type: checkpoint_spark_threat
actions:
  - action: notify.notify
    data:
      title: "Firewall: {{ trigger.event.data.kind }}"
      message: "{{ trigger.event.data.name }} ({{ trigger.event.data.value }})"
```

## Syslog (real-time security logs)

Option *Receive syslog* starts a UDP listener (default port **5140**; UniFi
Network already uses 5514). Two ways to feed it:

1. **Directly** – on the gateway, add a syslog server pointing to the Home
   Assistant host and port and enable sending security logs.
2. **Via a log server** – the gateway sends to e.g. Synology Log Center,
   rsyslog or syslog-ng, which forwards to Home Assistant. Add that server's
   IP under *Additional senders*.

Only datagrams from the gateway and the additional senders are accepted.
With *Forward syslog to* (`host:port`) every accepted message is passed on
unchanged – useful for a full archive on a NAS when the gateway supports only
one syslog server. IPS and malware **detections are stored** (default 90 days,
max 2000) and survive restarts; raw messages are kept in memory only.
See [SECURITY.md](SECURITY.md) for the hardening.

| Entity | Content |
|---|---|
| IPS events (last hour) | count; attributes `last_24h`, `ignored`, `recent` (last 20: time, name, severity, action, src, dst, cve, resource) |
| Firewall drops (last hour) | count; `last_24h`, `top_sources`, `top_services` |
| Scanned hosts (24 h) | from the anti-malware status; `hour`, `week` |
| Detected threats (24 h) | unique detections; `hour`, `week`, `recent_malware` |
| Detections (30 days) | stored IPS + malware detections; `last_24h`, `last_7d`, `daily`, `history` (last 100) |
| Syslog messages | counter since start; `products`, `dropped`, `rate_limited`, `forwarded`, `allowed_senders` |

IPS attacks (`kind: ips_attack`) and malware detections (`kind: malware_detected`)
fire `checkpoint_spark_threat` with `source: syslog` – at most once per hour for
the same attack and source. Sources listed in *Ignore sources* never fire events.

## Actions

| Action | Data | Response |
|---|---|---|
| `checkpoint_spark.refresh` | – | fetches all selected reports now |
| `checkpoint_spark.get_report` | `report_type` | `{report_type, fetched, report}` (decoded report) |
| `checkpoint_spark.show_command` | `command` (must start with `show`) | `{command, output}` |
| `checkpoint_spark.detections` | `days` (1–365), `kind` | `{count, detections}` (stored, newest first) |
| `checkpoint_spark.syslog_messages` | `limit` (1–200, default 50) | `{received, dropped, messages}` (newest first) |

All actions accept an optional `config_entry_id` when several gateways are configured.

## Dashboard

An example dashboard using only standard cards is in
[examples/dashboard.yaml](examples/dashboard.yaml).

## Diagnostics

**Settings → Devices & services → Check Point Quantum Spark → ⋮ → Download
diagnostics** returns the decoded reports and the parsed gateway values.
Username, password, serial number and public IP are always redacted. The
reports still contain internal IP addresses and host names – enable the option
*Redact network data in diagnostics* before sharing them publicly.

## Troubleshooting

Enable debug logging:

```yaml
logger:
  logs:
    custom_components.checkpoint_spark: debug
```

| Problem | Hint |
|---|---|
| Cannot connect | REST API enabled? Port 4434 reachable from Home Assistant? Administrator access allowed from the HA network? |
| Invalid username or password | Check user/password. **Administrator 2FA enabled?** The API login then always fails – see [gateway setup](docs/gateway-setup.md#3-two-factor-authentication-2fa) |
| Report failed | The administrator role may not be allowed to generate reports |

## Development

Tests: `pip install -r requirements_test.txt && pytest`.


See [docs/development.md](docs/development.md). The API calls used are
documented in [docs/api.md](docs/api.md).

## License

[MIT](LICENSE)
