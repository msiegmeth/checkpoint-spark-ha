# Gateway setup

Menu names can differ slightly between firmware versions.

## 1. Enable the REST API

Connect via SSH (or the WebUI's CLI console) and run in clish:

```
set rest-api mode on
show rest-api
```

The API listens on port **4434** (HTTPS, self-signed certificate).

## 2. Create an administrator for Home Assistant

WebUI → **Device → System → Administrators** (or **Device → Administrators**) → **New**

- Name: e.g. `ha-api`
- Strong, unique password
- Role: **Read-only administrator**

A read-only account guarantees on the gateway side that the integration
cannot change anything.

Verified on R81.10.17: a read-only administrator (`ROLE.RO`) may call
`generate-report`. If report generation fails with a read-only account on
your firmware, please open an issue with the firmware version.

## 3. Two-factor authentication (2FA)

The REST API login only accepts user and password – there is **no field for a
second factor**. If administrator 2FA is enabled on the gateway, every API
login is rejected (on R81.10.x with HTTP 500 `"Web server error"`, the same
answer as for a wrong password).

2FA for administrators is a **global** switch (`set admin-2fa on|off`, from
R81.10.10). Check Point documents no per-user, per-network or API exception.
So the integration only works with administrator 2FA **disabled**:

```
show admin-2fa
set admin-2fa off
```

Run this in **clish** as a super administrator (SSH). On some firmware the
WebUI refuses the change with "You have no privileges to change this
configuration" even for super administrators – clish works.

To compensate, restrict administrator access (next step) to a few trusted
IP addresses, e.g. your admin PC and the Home Assistant host, and use the
read-only account for the integration.

## 4. Allow access from Home Assistant

WebUI → **Device → Administrator Access**: make sure web/API access is
allowed from the network Home Assistant runs in (usually the internal
network).

## 5. Syslog for real-time events (optional)

Needed for single events with time, source, target and direction (IPS,
anti-malware status, firewall drops) – the REST API reports only totals.

**On the gateway** (WebUI, *Logs & Monitoring* → log server / syslog settings;
names differ slightly between firmware versions):

| Setting | Value |
|---|---|
| Syslog server | IP address of Home Assistant |
| Port / protocol | the port set in the integration (default **5140**), **UDP** |
| Send **system logs** | on |
| Send **security logs** | on (IPS, threat prevention, application control, firewall) |
| **Show obfuscated fields** | optional, see below |

**In Home Assistant:** integration options → *Receive syslog* on, same port.
If the gateway cannot send to Home Assistant directly, point it to a log server
(e.g. Synology Log Center, rsyslog) that forwards to Home Assistant and add that
server under *Additional senders*.

**Show obfuscated fields:** by default the gateway replaces some fields with
`*** Confidential ***` (e.g. application IDs, matched category) and may omit
details of anti-virus / DNS-trap events. Enabling it can provide those details –
at the cost of more personal data (full URLs, possibly user names) in the logs.
The integration keeps raw messages in memory only and stores just the
whitelisted fields of detections.

**Known limitation (R81.10.17):** anti-virus / DNS-trap blocks arrived only as
the periodic *Anti Malware* status (counts) or as short records without malware
name and host. Those blocks are therefore shown as report totals; IPS events come
with full details.

Check reception in Home Assistant: sensor *Syslog messages* (counter, products,
dropped senders) or the action `checkpoint_spark.syslog_messages`.

## 6. OpenTelemetry / Skyline for health metrics (optional, preview)

The gateway can export CPView health metrics (CPU load, memory, connections,
interfaces, …) with OpenTelemetry ("Skyline", early access on Spark from
R81.10.08). The integration receives them as **Prometheus remote write**.

**In Home Assistant:** integration options → *Receive OpenTelemetry* on, choose
a user and a password (≥ 12 characters).

**On the gateway:** *Logs & Monitoring* → *Diagnostics* → **OpenTelemetry**
(clish: `set open-telemetry url … username … password … is-active on`):

| Setting | Value |
|---|---|
| Monitor this appliance using OpenTelemetry | on |
| URL | `http://<home-assistant>:8123/api/checkpoint_spark/telemetry` (or your `https://` address) |
| Client authentication | the user/password from the integration options |
| Server authentication | only for `https://` with a private CA: upload that CA certificate |

The gateway downloads its OpenTelemetry agent from Check Point, so it needs
internet access. Only POSTs from the gateway's IP with the right credentials
are accepted; payloads are size-limited and only the newest value per series is
kept in memory. Check reception: sensor *Telemetry series* or the action
`checkpoint_spark.telemetry_metrics`.

## 7. Test (optional)

```sh
curl -k -X POST https://GATEWAY:4434/web-api/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"ha-api","password":"…"}'
```

A JSON answer with `sid` means the account works. Log out afterwards:

```sh
curl -k -X POST https://GATEWAY:4434/web-api/logout -H 'x-chkp-sid: <sid>'
```
