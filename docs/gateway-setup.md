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

> If report generation fails with a read-only account on your firmware,
> please open an issue with the firmware version. Only grant a higher role
> if you accept the risk.

## 3. Allow access from Home Assistant

WebUI → **Device → Administrator Access**: make sure web/API access is
allowed from the network Home Assistant runs in (usually the internal
network).

## 4. Test (optional)

```sh
curl -k -X POST https://GATEWAY:4434/web-api/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"ha-api","password":"…"}'
```

A JSON answer with `sid` means the account works. Log out afterwards:

```sh
curl -k -X POST https://GATEWAY:4434/web-api/logout -H 'x-chkp-sid: <sid>'
```
