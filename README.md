# mtg-multi

A fast, censorship-resistant [Telegram MTProto proxy](https://core.telegram.org/mtproto),
forked from [9seconds/mtg](https://github.com/9seconds/mtg) and extended for
running one instance for many users.

Upstream mtg is a single-secret proxy. mtg-multi keeps everything that makes mtg
good — FakeTLS, domain fronting, anti-replay, traffic-shape mimicry — and adds
the pieces you need to run a shared proxy: named per-user secrets, live per-user
traffic stats, a management API, hot reload, connection throttling, and the
sponsored-channel ad-tag that mtg v2 removed.

## What's different from upstream

- **Multiple secrets** — one named secret per user, each with its own fronting host.
- **Per-user stats** — a JSON endpoint with live connection and byte counters.
- **Management API** — add, remove, and re-key secrets and the ad-tag at runtime.
- **Hot reload** — swap the secret set from the config file without dropping users.
- **Sponsored channel (ad-tag)** — the promoted-channel feature, back again.
- **Connection throttling** — automatic fair-share per-user connection caps.
- **Per-user quotas, expiry & disable** — data caps (with optional monthly reset),
  a validity deadline, and an on/off switch, persisted across restarts.
- **Public IP override** and **Docker-style environment variables**.
- **SIGHUP reload** — the same hot reload as `POST /reload`, triggered by a signal.
- **Secured (`dd`) handshakes** — the same keys work with `ee` and `dd` links.
- **Warm Telegram DC pool** and optional **secured-response shaping**.
- **Config overlay** — extra settings under a config written by 3X-UI.

Everything else — FakeTLS, domain fronting, the doppelganger traffic mimic,
SOCKS5 proxy chaining, IP blocklists/allowlists, Prometheus and statsd metrics —
works exactly as in upstream. See the [upstream README](https://github.com/9seconds/mtg)
for the shared internals.

## Table of contents

- [Quick start](#quick-start)
- [Running with Docker](#running-with-docker)
- [Features](#features)
  - [Multiple secrets](#multiple-secrets)
  - [Per-user stats API](#per-user-stats-api)
  - [Hot secret reload](#hot-secret-reload)
  - [Secrets & ad-tag management API](#secrets--ad-tag-management-api)
  - [API authentication](#api-authentication)
  - [Sponsored channel (ad-tag)](#sponsored-channel-ad-tag)
  - [Connection throttling](#connection-throttling)
  - [Per-user quotas, expiry & disable](#per-user-quotas-expiry--disable)
  - [Public IP override](#public-ip-override)
  - [Environment variables](#environment-variables)
  - [Secured (dd) handshakes](#secured-dd-handshakes)
  - [Warm Telegram DC pool](#warm-telegram-dc-pool)
  - [Small-segment ServerHello (client MSS)](#small-segment-serverhello-client-mss)
  - [Config overlay](#config-overlay)
- [Running under 3X-UI](#running-under-3x-ui)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Credits](#credits)

## Quick start

Download a binary from [Releases](https://github.com/mhsanaei/mtg-multi/releases),
or build from source (requires Go 1.26+):

```console
git clone https://github.com/mhsanaei/mtg-multi.git
cd mtg-multi
go build          # produces ./mtg-multi
```

If you use [mise](https://mise.jdx.dev/), `mise install && mise run build` sets
up the toolchain and builds the same binary.

Generate a secret for each user. The hostname is the site you front behind: it
does not have to point at your server, but it should be a real, reachable HTTPS
site — the classic choice is a large CDN such as `storage.googleapis.com`:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Write a minimal config:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] must be the LAST section in the global scope. In TOML, every key
# after a [section] header belongs to that table, so any top-level option
# placed below [secrets] would be parsed as a secret.
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

Run it:

```console
mtg-multi run /etc/mtg/config.toml
```

Then print the connection links and QR codes for your users:

```console
mtg-multi access /etc/mtg/config.toml
```

## Running with Docker

The image is published to the GitHub Container Registry and ships a working
default config, so it can be configured entirely from environment variables in
the style of the official `telegrammessenger/proxy` image:

```console
docker run -d --name mtg -p 443:443 \
    -e SECRET=00112233445566778899aabbccddeeff \
    -e SECRET_HOST=storage.googleapis.com \
    -e TAG=3f40462915a3e6026a4d790127b95ded \
    -e MTG_BIND_TO=0.0.0.0:443 \
    ghcr.io/mhsanaei/mtg-multi:latest
```

To run with a full config file instead, mount it over the bundled default at
`/config/config.toml`:

```console
docker run -d --name mtg -p 443:443 \
    -v /etc/mtg/config.toml:/config/config.toml:ro \
    ghcr.io/mhsanaei/mtg-multi:latest
```

See [Environment variables](#environment-variables) for the full list.

## Features

### Multiple secrets

Define named secrets in the config, one per user. Each name is used as the label
in per-user stats, and each secret may front behind a different hostname.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

The single-secret `secret = "..."` form from upstream still works and is treated
as one secret named `default`.

### Per-user stats API

Set `api-bind-to` to start a small HTTP server (bind it to loopback unless you
also set an [API token](#api-authentication)):

```toml
api-bind-to = "127.0.0.1:9090"
```

```console
curl http://127.0.0.1:9090/stats
```

```json
{
  "started_at": "2026-03-29T10:30:00Z",
  "uptime_seconds": 3600,
  "total_connections": 15,
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-03-29T11:25:30Z",
      "active_ips": ["192.0.2.10"]
    }
  }
}
```

`last_seen` is `null` for a user who has never connected. `active_ips` lists the
client addresses of the user's live connections. The `throttle` object is
included only when [throttling](#connection-throttling) is configured.

The response also carries `secrets_sha256`: the SHA-256 of the lines
`name=<secret hex>` sorted by name and joined with `\n`. It changes on every
applied update of the secret set (including a re-key under the same name), so an
external sync can verify that a reload has really been applied.

### Hot secret reload

The `api-bind-to` listener also serves a reload endpoint, so the `[secrets]` set
can change without restarting the proxy:

```console
curl -X POST http://127.0.0.1:9090/reload
```

On success it re-reads the same config file passed to `mtg-multi run` and swaps
the secret set in atomically:

- added secrets start working immediately;
- connections whose secret was removed or re-keyed are closed;
- every other user stays connected and their stats counters carry over.

Only `[secrets]`, `ad-tag`, `[secret-ad-tags]`, and `[secret-limits]` are
hot-applied. Changing the
bind address, domain fronting, network, or throttle settings still needs a
restart.

Responses: `200 {"status":"ok"}` on success; `500` if the config cannot be read
(the current set stays active); `503` when the proxy was started without a config
file (`simple-run`); `405` for a non-POST request.

`SIGHUP` does the same without the API (not available on Windows):

```console
kill -HUP $(pidof mtg-multi)
# or with systemd: ExecReload=/bin/kill -HUP $MAINPID, then
systemctl reload mtg-multi
```

`SIGHUP`, `POST /reload` and the management API below all end in one
mechanism, so they lead to the same state: a handshake that started on the old
set does not pass after its secret was removed or re-keyed, a removed user is
not kept in `/stats`, and a user that became disabled or expired is
disconnected. Write the new config atomically (to a temporary file, then `mv`),
so mtg never reads a half-written file.

### Secrets & ad-tag management API

The same listener exposes CRUD endpoints so you can manage secrets and the ad-tag
at runtime, without editing the file or restarting:

| Method & path | Action |
|---|---|
| `GET /secrets` | List secrets (`name`, `secret`, `host`, `ad_tag`, `effective_ad_tag`, plus `quota`/`quota_used`/`quota_remaining`/`expires_at`/`disabled` when set). |
| `POST /secrets` | Add or update one: `{"name","secret","ad_tag"?,"quota"?,"quota_reset"?,"expires"?,"disabled"?}`. |
| `PUT /secrets` | Replace the whole set: `{"secrets":{name:{secret,ad_tag?,quota?,quota_reset?,expires?,disabled?}},"ad_tag"?}`. |
| `DELETE /secrets/{name}` | Remove one (`404` if unknown, `409` if it is the last one). |
| `POST /secrets/{name}/reset-quota` | Zero the secret's used-bytes counter (`404` if unknown). |
| `GET /adtag` | Read the global ad-tag: `{"ad_tag":"<hex>"\|null}`. |
| `PUT /adtag` | Set the global ad-tag: `{"ad_tag":"<32 hex chars>"}`. |
| `DELETE /adtag` | Clear the global ad-tag. |

These go through the same atomic-swap machinery as `/reload`: a changed secret
key closes that user's connections, while an ad-tag-only change does not.

Direct API mutations are **in-memory only** — a later `POST /reload` (or a
restart) re-reads the config file and overrides them. Treat the file as the
source of truth and the API as a live override.

### API authentication

By default the API is unauthenticated and protected only by binding to loopback.
Because it can mutate secrets, you can require a bearer token on **every**
endpoint:

```toml
api-token = "change-me"
```

```console
curl -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

Missing or wrong tokens get `401`. When `api-token` is unset, behavior is
unchanged (no auth). Always set a token if the API is reachable from anything but
localhost.

### Sponsored channel (ad-tag)

Upstream mtg v2 dropped the promoted-channel feature; mtg-multi brings it back.
When an ad-tag is set, matching clients are routed through Telegram **middle
proxies** (the RPC protocol) instead of directly to the data centers, and your
sponsored channel appears at the top of their chat list.

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"   # this proxy's reachable public address
```

One global tag applies to every secret; you can override it per secret:

```toml
[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

**Getting a tag.** Register your proxy with [@MTProxybot](https://t.me/MTProxybot)
to obtain a 32-character hex `ad_tag`. When the bot asks for your secret, give it
the **bare 16-byte key only** — 32 hex characters, without the `ee` prefix and
without the appended hostname. For example, from the secret
`ee`**`3610182353be658466cea76f358bf9bb`**`7777772e...` you paste only
`3610182353be658466cea76f358bf9bb`. Pasting the full FakeTLS secret makes the bot
reply *"Incorrect secret value. It must contain 32 hex characters"* — that is the
bot's format requirement, not an error in your proxy.

**Requirements and behavior.**

- The middle-proxy path adds one network hop and needs a reachable **public IP**.
  On a host behind NAT or with multiple addresses, set `public-ipv4` /
  `public-ipv6` — the proxy's source address (and port) are mixed into the RPC
  key schedule, so the middle proxy must see the address you advertise. A machine
  behind a port-rewriting NAT cannot complete this handshake; run on a host with
  a real public IP (a VPS).
- If a middle proxy cannot be reached, that connection **falls back to a direct
  DC connection** (logged as a warning) so the client stays online — the sponsored
  channel just won't show for that session.
- The middle-proxy secret and address list are fetched from Telegram lazily on
  first use and refreshed hourly, so a proxy without an ad-tag never contacts
  those endpoints.

### Connection throttling

Automatic per-user connection limits protect the server from overload. A
background goroutine recomputes caps every few seconds using a fair-share
algorithm: light users keep all their connections, and the remaining budget is
split equally among heavy consumers. New connections from over-cap users are
rejected; existing connections are never killed.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Example — limit 100, with users A=1, B=1, C=90, D=110: A and B stay at 1, and the
remaining budget of 98 is split so C and D are each capped at 49.

Throttle state is exposed in the stats response:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

### Per-user quotas, expiry & disable

Each named secret can carry governance limits — a data quota, a validity
deadline, and an on/off switch — so you can run mtg-multi as a reseller or
multi-tenant proxy. Add a `[secret-limits.<name>]` table for any secret in
`[secrets]`; a secret without one is unlimited, never expires and is enabled.

```toml
# Persist quota usage across restarts (optional but recommended for quotas).
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"            # human size or a bare byte count; omit for unlimited
quota-reset = "monthly"   # "none" (default, lifetime cap) or "monthly"
expires = "2026-12-31"    # RFC3339 or YYYY-MM-DD; omit for never
disabled = false          # true rejects the secret without removing it

[secret-limits.bob]
quota = "500MB"
```

When a user is over quota, past its expiry, or disabled, new connections are
transparently routed to the **fronting domain** — exactly like a wrong secret —
so a prober cannot tell a limited user from an invalid one. Enforcement happens
at connection time: an in-progress session is not cut off mid-stream, but
disabling or expiring a secret (via reload or the API) closes its live
connections immediately. A quota overrun never kills an active session.

Usage is exposed per user in `/stats` and `/secrets`:

```json
{
  "users": {
    "alice": {
      "connections": 2,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "quota_used": 3145728,
      "quota": 10737418240,
      "quota_remaining": 10734272512,
      "quota_reset": "monthly",
      "expires_at": "2026-12-31T00:00:00Z"
    }
  }
}
```

Set `usage-state-file` so `quota_used` survives restarts; it is flushed
atomically every ~30 seconds and on shutdown. With `quota-reset = "monthly"` the
counter resets at the start of each calendar month. Clear a user's usage
manually with `POST /secrets/{name}/reset-quota`. Limits set through the
management API are in-memory only and are overridden by the next reload — the
config file remains the source of truth.

### Public IP override

Useful when automatic detection via ifconfig.co is unavailable, or when the
address the outside world sees differs from any local interface.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

These addresses are used by `mtg-multi access` to build links, by
`mtg-multi doctor` to validate the SNI-to-DNS match, and — when an ad-tag is set
— as this proxy's own address in the middle-proxy handshake.

### Environment variables

For parity with the official
[telegrammessenger/proxy](https://hub.docker.com/r/telegrammessenger/proxy/)
image, `mtg-multi run` overlays a few environment variables on top of the config
file. The environment always wins over the file, and it is re-applied on every
config read, so an env-pinned secret or tag survives a `POST /reload`.

| Variable | Meaning |
|---|---|
| `SECRET` | Proxy secret. Either a full mtg secret (`ee…` hex or base64) or a bare 16-byte hex key in the official-image format — the latter also needs `SECRET_HOST`. Replaces the whole `[secrets]` set and `[secret-ad-tags]`. |
| `SECRET_HOST` | Domain-fronting hostname combined with a bare 16-byte `SECRET` into a FakeTLS secret. Ignored when `SECRET` is already a full secret. |
| `TAG` | Advertising tag from [@MTProxybot](https://t.me/MTProxybot); same as `ad-tag` in the config. An empty value clears the tag. Like the official image, it is not persisted — provide it on every run. |
| `MTG_BIND_TO` | Comma-separated `host:port` list overriding `bind-to`. |

The `MTG_`-prefixed variants (`MTG_SECRET`, `MTG_SECRET_HOST`, `MTG_TAG`) take
precedence over the bare names, so a generic name like `SECRET` in a shell can't
be captured by accident outside a container.

`WORKERS` and `SECRET_COUNT` from the official image are not applicable — one Go
process already uses every CPU core, and multiple secrets are configured through
`[secrets]` or the API. Setting either is ignored with a startup warning.

### Secured (dd) handshakes

The same named 16-byte keys work with either FakeTLS (`ee`) or secured (`dd`)
Telegram links. The proxy detects the transport and matches a secured handshake
against the configured keys, so `config.toml` keeps `ee` secrets. Per-user
limits apply to secured connections too. Secured mode is on by default; turn
it off with `[secured] enabled = false` or `MTG_SECURED=0`.

`[secured] shape = true` (or `MTG_DD_SHAPE=on`) delays the first secured server
response by 30-100 ms and splits that first write into 88-byte fragments.
FakeTLS and later bulk writes are unchanged.

### Warm Telegram DC pool

The proxy keeps ready connections to the Telegram DCs that clients actually use,
so a client does not wait for a cold dial. It is on by default.

```toml
[dc-pool]
enabled = true          # MTG_DC_POOL=0/off disables
size = 2                # MTG_DC_POOL_SIZE
dcs = [2, -2, 203, 4, -4]  # MTG_DC_POOL_DCS="2,-2,203"; negative ids are media DCs
```

For `[secured]` and `[dc-pool]` a key in the config wins over the environment
variable, and the variable wins over the default.

### Small-segment ServerHello (client MSS)

Some DPI boxes recognise the FakeTLS ServerHello when it arrives in full-size
TCP segments, but not when it is split into small ones. On Linux mtg-multi can
send only the ServerHello in small segments and keep full-size segments for
the rest of the session:

```toml
[network]
client-mss = 92         # MSS used for the ServerHello; 0 (default) disables
client-mss-bulk = 1400  # MSS for the rest of the session (default 1400)
```

- `client-mss` is `0` or `48..1460`; `client-mss-bulk` is `0` or
  `536..65495` and must be greater than `client-mss`.
- With `client-mss-bulk > 0` the listening socket gets `TCP_MAXSEG =
  client-mss-bulk`, and the ServerHello is written in chunks that fit one
  segment at `client-mss` (minus TCP options), each chunk only after the
  previous one has left the socket queue, so the kernel cannot merge them.
  With `client-mss = 92` and TCP timestamps that is 80 bytes per segment.
- `client-mss-bulk = 0` puts `TCP_MAXSEG = client-mss` on the listening
  socket for the whole session (like `iptables TCPMSS --set-mss` on the client
  SYN); `client-mss` must then be at least 88 (kernel minimum).
- Linux does not raise the segment size of an established connection with
  `setsockopt(TCP_MAXSEG)`: the size is fixed during the handshake. That is why
  the bulk MSS goes on the listener and only the ServerHello is split.
- Secured (`dd`) handshakes have no server response; see `[secured] shape`.
- The listener options are read at start; changing them needs a restart. The
  keys work from `MTG_CONFIG_OVERLAY` too. Ignored outside Linux.

### Config overlay

`MTG_CONFIG_OVERLAY=/path/to/overlay.toml` merges a second TOML file **under**
the config passed to `mtg-multi run`:

- a key from the main config always wins; only missing keys come from the
  overlay;
- tables are merged deeply (`[defense.anti-replay]` from the overlay is added
  next to `[defense.blocklist]` from the main config);
- users never come from the overlay: `secret`, `[secrets]`, `[secret-limits]`
  and `[secret-ad-tags]` in it are ignored.

The overlay is applied on every config read: start, `SIGHUP`, `POST /reload`,
`doctor` and `access`. A missing or broken overlay stops the start with an
error; on a reload it is treated like a broken config, and the current state is
kept.

## Running under 3X-UI

The 3X-UI panel (v3.9+) runs `mtg-linux-amd64 run <config>` for each MTProto
inbound, writes a minimal config itself (`bind-to`, `api-bind-to`, `api-token`,
`[secrets]`, `[secret-limits]`, ...) and applies client changes through
`PUT /secrets` with the bearer token. This build keeps that API, so it can
replace the panel's binary, and adds node settings through the overlay.

1. Put the binary where the panel looks for it: `mtg-<os>-<arch>` in the
   panel's bin folder (`bin` under the x-ui working directory, usually
   `/usr/local/x-ui/bin`, or `XUI_BIN_FOLDER`). A panel update may bring its
   own binary back, so re-check it after updating x-ui.

   ```console
   install -m 755 mtg-multi /usr/local/x-ui/bin/mtg-linux-amd64
   ```

2. Write the overlay with settings the panel does not manage:

   ```toml
   # /etc/mtg/overlay.toml
   concurrency = 8192
   prefer-ip = "prefer-ipv4"
   tolerate-time-skewness = "5s"

   [secured]
   enabled = true

   [dc-pool]
   enabled = true

   [stats.prometheus]
   enabled = true
   bind-to = "127.0.0.1:3129"

   [defense.blocklist]
   enabled = false

   [defense.anti-replay]
   enabled = true

   [network.timeout]
   tcp = "5s"
   idle = "1m"
   ```

3. mtg inherits the environment of the x-ui process, so set it with a systemd
   drop-in:

   ```console
   systemctl edit x-ui
   ```

   ```ini
   [Service]
   Environment=MTG_CONFIG_OVERLAY=/etc/mtg/overlay.toml
   ```

   ```console
   systemctl restart x-ui
   ```

A key the panel writes (for example `prefer-ip`) wins over the overlay. Run
several MTProto inbounds with one overlay only for settings that may be shared:
a `[stats.prometheus] bind-to` port can be bound by one process only.

## Command reference

| Command | Description |
|---|---|
| `mtg-multi generate-secret [--hex] <hostname>` | Generate a new secret for the given fronting hostname. `--hex`/`-x` prints hex instead of base64. |
| `mtg-multi run <config>` | Run the proxy from a config file (supports the full feature set and hot reload). |
| `mtg-multi simple-run <bind-to> <secret>` | Run without a config file, from flags only (no `[secrets]`, no reload). |
| `mtg-multi access [--ipv4 IP] [--ipv6 IP] [--port N] [--hex] <config>` | Print `tg://` / `t.me` links and QR-code URLs for the configured secrets. |
| `mtg-multi doctor [--skip-native-check] <config>` | Check connectivity, clock skew, fronting reachability, and SNI-to-DNS match. Run this first when something is off. |
| `mtg-multi version` | Print the version. |

## Configuration

[example.config.toml](example.config.toml) documents every option with its
default value and inline notes. A real config only needs the options you actually
change — every key has a sensible default.

## Credits

mtg-multi is a fork of [9seconds/mtg](https://github.com/9seconds/mtg) by Sergey
Arkhipov and contributors. All of the core proxy engineering is theirs; this fork
adds the multi-user layer on top. The middle-proxy (ad-tag) implementation is
ported from the last mtg v1 release that shipped it.
