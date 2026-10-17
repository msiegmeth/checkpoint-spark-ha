# CLAUDE.md – checkpoint-spark-ha

## Ziel
HA-Custom-Integration `checkpoint_spark`: liest über die lokale REST API eines
lokal verwalteten Check Point Quantum Spark die Security Reports
(`generate-report`), stellt Kennzahlen als Sensoren bereit, Beispiel-Dashboard
unter `examples/`.

## API
Siehe `docs/api.md`. Kurz: POST `https://<host>:4434/web-api/<cmd>`, Header
`x-chkp-sid` nach `login`; `reportData` = base64-JSON, Antwort Objekt oder
Liste; Fehllogin 400 oder 401.

## Layout
HACS-kompatibel: `custom_components/checkpoint_spark/` im Root, `docs/`,
`examples/`, `.github/workflows/` (hassfest + HACS-Validierung, Release bei Tag).

## Entwicklungsablauf (diese Installation)
- Repo: `/homeassistant/dev/checkpoint-spark-ha` (Gitea `gitadmin/checkpoint-spark-ha`,
  privat) → Push-Mirror → GitHub `msiegmeth/checkpoint-spark-ha` (öffentlich, HACS-Quelle).
  Auf GitHub nie direkt ändern.
- Test: `/homeassistant/custom_components/checkpoint_spark` ist ein **relativer** Symlink
  auf den Repo-Ordner (Core-Container mountet als `/config`). Im HA-Config-Repo per
  `.gitignore` ausgeschlossen.
- Python-Änderung → HA-Neustart (ankündigen). Report-Struktur über Diagnostics
  (`/api/diagnostics/config_entry/<id>`) ansehen.
- Release: `manifest.json`-Version + CHANGELOG, Tag `vX.Y.Z`, push → GitHub-Action
  erstellt Release → HACS bietet Update an.

## Regeln
- Am Gateway NUR `login`, `logout`, `generate-report` und Clish `show …`. Nie Config ändern.
- Keine Zugangsdaten, Session-IDs oder ungeschwärzten Reportdaten committen.
  `docs/report-sample.json` nur anonymisiert (IPs, Hostnamen, Benutzer).
- Keine externen Requirements; aiohttp aus HA. Aktuelle HA-Konventionen
  (runtime_data, Coordinator mit config_entry, has_entity_name, Übersetzungen de/en).
- Große Attribute in `_unrecorded_attributes`.
