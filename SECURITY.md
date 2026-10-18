# Security

## Gateway access

- Only `login`, `logout`, `generate-report` and clish commands starting with
  `show` are used. The `show_command` action refuses anything else.
- Use a **read-only** administrator. The REST API cannot do 2FA – restrict
  administrator access on the gateway to a few trusted IPs instead.
- `show` outputs contain secrets (PPPoE password and hash, setup Wi-Fi
  password). The integration keeps whitelisted fields only and never stores,
  logs or exposes raw outputs (diagnostics included).

## Syslog receiver

The receiver is **off by default**. When enabled:

| Risk | Mitigation |
|---|---|
| Foreign senders | Only datagrams from the gateway and the configured relays are accepted; everything else is dropped and counted |
| Spoofed source IP (UDP) | Cannot be ruled out for plain UDP syslog inside the LAN. Worst case is false alarms – the integration only fires events and updates sensors, it never acts on messages. **Never expose the port to the internet** (no port forwarding) |
| Flooding / DoS | Rate limit 500 messages/s, max 8 KB per datagram, all buffers bounded, max 30 events per hour; excess is dropped and counted |
| Parser attacks | Linear regular expressions, input cut before parsing, control characters removed, keys ≤ 64 and values ≤ 500 characters |
| Dashboard injection (XSS) | Values are plain data; dashboards must HTML-escape them (the example does) |
| Forwarding loops / amplification | Only accepted messages are forwarded, unchanged and rate-limited; forwarding to this receiver or to an allowed sender on the same port is refused |
| Stored data | Only IPS / malware detections (validated, bounded, retention configurable, max 2000) in `.storage`; raw messages are kept in memory only |

## OpenTelemetry receiver

Off by default. The endpoint `/api/checkpoint_spark/telemetry` does not use a
Home Assistant token (the gateway only supports basic auth). It accepts requests
only from the configured gateway IP **and** with the user/password from the
options (constant-time comparison; password ≥ 12 characters). Bodies are limited
to 4 MB compressed / 32 MB uncompressed, at most 5000 series are kept (newest
value only, in memory). Malformed payloads are rejected. Use `https://` if the
connection leaves your LAN.

## Reporting

Please open a GitHub issue without sensitive data, or contact the
maintainer via the profile on GitHub for anything that should not be public.
