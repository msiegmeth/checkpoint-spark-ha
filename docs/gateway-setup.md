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

## 5. Test (optional)

```sh
curl -k -X POST https://GATEWAY:4434/web-api/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"ha-api","password":"…"}'
```

A JSON answer with `sid` means the account works. Log out afterwards:

```sh
curl -k -X POST https://GATEWAY:4434/web-api/logout -H 'x-chkp-sid: <sid>'
```
