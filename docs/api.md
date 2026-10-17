# Used API calls

Base URL: `https://<host>:4434/web-api/<command>`, always `POST` with
`Content-Type: application/json`. After login every call carries the header
`x-chkp-sid: <sid>`.

| Command | Body | Answer |
|---|---|---|
| `login` | `{"user": "…", "password": "…"}` | `sid`, `role`, `read-only`, `session-timeout` (≈ 10 min). Wrong credentials: HTTP 400/401, on some firmware HTTP 500 `system_error` |
| `generate-report` | `{"type": "hourly\|daily\|weekly\|monthly"}` | `reportData`: base64-encoded JSON. The answer can be an object or a list with one object |
| `run-clish-command` | `{"script": "<base64 clish>"}` | `output`: base64. **Only `show …` commands are used** |
| `logout` | none | – |

Nothing else is called. The client (`custom_components/checkpoint_spark/api.py`)
refuses clish commands that do not start with `show`.

## Report structure

An anonymised sample is in [report-sample.json](report-sample.json).
The integration is written to tolerate missing fields and firmware
differences: absent values lead to `unknown`, not to errors.
