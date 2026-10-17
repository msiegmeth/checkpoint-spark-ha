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
- Home Assistant 2025.8 or newer

See [docs/gateway-setup.md](docs/gateway-setup.md) for the gateway side.

## Installation

### HACS (recommended)

1. HACS → ⋮ → **Custom repositories**
2. Repository: `https://github.com/msiegmeth/checkpoint-spark-ha`, type **Integration**
3. Install **Check Point Quantum Spark**, then restart Home Assistant.

New releases are then offered as updates in Home Assistant.

### Manual

Copy `custom_components/checkpoint_spark` into the `custom_components`
folder of your Home Assistant configuration and restart.

## Configuration

**Settings → Devices & services → Add integration → Check Point Quantum Spark**

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
| Polling interval | 15 min | 5 – 1440 min |

Generating a report costs some CPU on the gateway. Keep the interval
moderate, especially when several report types are selected.

## Entities

All entities belong to one device per gateway.

| Entity | Description |
|---|---|
| `<Report type> report` (timestamp, diagnostic) | When the report of this type was fetched last |

Key figures from the reports (threats, top lists, …) are being added; see
the [CHANGELOG](CHANGELOG.md). Large lists are exposed as attributes and are
excluded from the recorder.

## Dashboard

An example dashboard using only standard cards is in
[examples/dashboard.yaml](examples/dashboard.yaml).

## Diagnostics

**Settings → Devices & services → Check Point Quantum Spark → ⋮ → Download
diagnostics** returns the decoded reports. Username and password are
redacted, but the reports contain internal IP addresses and host names –
review before sharing.

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
| Invalid username or password | Note that the Spark may answer wrong logins with HTTP 400 or 401 |
| Report failed | The administrator role may not be allowed to generate reports |

## Development

See [docs/development.md](docs/development.md). The API calls used are
documented in [docs/api.md](docs/api.md).

## License

[MIT](LICENSE)
