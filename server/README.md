# Server — real-TLS relay with subscriptions

A stdlib-only Python relay (`mtrelay.py`) that terminates **genuine TLS** on `443`
and forwards the custom client's MTProto stream to the real Telegram
datacenters. On the wire the connection is indistinguishable from ordinary HTTPS
to your domain, so pattern-based DPI — which detects Telegram's own Fake-TLS
proxies — has nothing to match on.

```
custom client --REAL TLS(your-domain:443)--> mtrelay --> Telegram DC (1..5)
                                                 ├── onboarding tunnel --> my.telegram.org
                                                 └── everything else   --> cover site
```

It can run in two modes:

* **Self-hosted** (default): any client that knows your domain is carried. This
  is the original behaviour and needs no database.
* **Subscription**: clients present a token; the relay checks expiry, device
  count and quota, meters traffic, and stops carrying a lapsed subscription.
  Set `ALLOW_V1=0` to refuse token-less clients.

## Requirements

* A domain name pointing (A record) at this server.
* A valid TLS certificate for that domain (Let's Encrypt is fine).
* Docker + Docker Compose.
* The server must be able to reach the Telegram DC IP ranges. If your host is
  itself blocked from Telegram, see **Blocked hosts** below.

## 1. Get a certificate

Any method works — you just need `fullchain.pem` + `privkey.pem`. With certbot:

```bash
sudo certbot certonly --standalone -d relay.example.com
mkdir -p certs
cp /etc/letsencrypt/live/relay.example.com/fullchain.pem certs/
cp /etc/letsencrypt/live/relay.example.com/privkey.pem   certs/
```

If you use client-side certificate pinning (see below), renew with
`--reuse-key`, or plan a pin rotation: a new key changes the pin and every
pinned client will refuse to connect.

`SIGHUP` reloads the certificate in place, so renewal no longer needs a restart:

```bash
docker compose kill -s HUP mtrelay
```

## 2. Run

```bash
docker compose up -d --build
docker compose logs -f mtrelay
```

Logs are one JSON object per line: `listening`, then `open` / `close` / `mask` /
`reject` per connection.

## 3. Issue a subscription

`relayctl` talks to the SQLite database directly; the relay picks up changes
within `AUTH_RELOAD_SEC`, or immediately when `relayctl` can signal it.

```bash
# inside the container so it shares /data with the relay
docker compose exec mtrelay python3 relayctl.py \
    issue --days 30 --devices 2 --label "alice" --host relay.example.com
```

It prints, once:

```
  token:      A7K2P9XXXXXXX-XXXXXXXXXXXXX
  setup code: relay.example.com|A7K2P9XXXXXXX-XXXXXXXXXXXXX|BMI3
```

The **setup code** is the single string the customer types into the app. Only
`sha256(token)` is stored, so a lost code cannot be recovered — use
`relayctl rotate` to issue a replacement.

Its full form is `host[:port][@ip]|TOKEN|CHECK`. The optional `:port` lets a
staging relay run beside a production one on the same hostname and certificate
(`--port 8443`), and `@ip` pins an address for networks with a poisoned
resolver. `CHECK` is a 4-character checksum, so a mistyped code fails
immediately with "check the code" instead of failing to connect — which on this
product is indistinguishable from "the relay is blocked here".

Common operations:

```bash
relayctl list                       # active subscriptions
relayctl show   <tok>               # one subscription, its devices and usage
relayctl extend <tok> --days 30
relayctl set    <tok> --devices 3 --quota 100G --period month
relayctl suspend <tok> / resume <tok>
relayctl revoke <tok> --reason "chargeback"
relayctl forget-device <tok> <hex>  # free a device slot ("I got a new phone")
relayctl usage  <tok> --days 30
relayctl prune  --older-than 30     # delete long-revoked rows
```

`<tok>` accepts a full token, a unique prefix, or `#id`.

### What a client sees when something is wrong

| situation | what the relay does |
|---|---|
| valid subscription | carries the traffic |
| expired / suspended / over quota / too many devices | sends a status frame the app turns into a "renew" screen |
| **unknown or malformed token** | silently splices to the cover site, exactly like a browser or a probe |

That last row is deliberate and load-bearing: a censor probing the endpoint with
a made-up token must not be able to tell this server apart from the website it
fronts. It also means the app cannot distinguish "bad token" from "blocked
network", so its error text must not claim to know which.

Note that `revoke` keeps the row so the customer still gets an explanation.
`prune` deletes it, after which the token becomes unknown and is silently
masked — the right end state, but not a good first response.

## Optional: cover site (probe resistance)

Set `MASK_HOST` / `MASK_PORT` to a real website you host. Any connection that is
not a recognised client is then transparently proxied to that site, so the
endpoint serves genuine content to anyone who looks. **Without it those
connections are dropped, which is itself a fingerprint** — configure it.

## Optional: web admin panel

`ADMIN_UI=1` serves the whole of `relayctl` — issue, extend, set, suspend,
resume, rotate, revoke, devices, usage, audit, prune — as a web page, on a
32-character random path:

```bash
relayctl adminurl --host relay.example.com --port 443
```

It is served by the relay itself, on the same port, deliberately: a request
whose path does not match falls through to the **cover site**, byte for byte,
exactly as an unknown token does. A wrong URL is not a 404 and not a login
form — it is indistinguishable from a domain that has no panel at all, so
there is nothing for a scanner to find. `relay.log` records it as an ordinary
`mask` event. This is also why `MASK_HOST` is not optional if you enable the
panel: without a cover site those requests are dropped, which *is* a signal.

**The URL is the only credential.** Anyone holding it can issue and revoke
subscriptions. It is never written to the log, the page loads no external
resource (so it cannot leak through `Referer`), responses are `no-store` and
`no-referrer`, and `adminurl --rotate` invalidates a leaked link — the old one
starts masking immediately. If that threat model is too loose for you, leave
`ADMIN_UI` off and reach `relayctl` over SSH, or bind the relay's admin to
localhost and use `ssh -L`.

Issued codes are shown exactly once, as on the CLI: the database stores only a
SHA-256, so the panel *cannot* redisplay a token even when asked.

## Optional: certificate pinning

The native TLS client does not verify the relay's certificate chain. That was
harmless while the connection carried only end-to-end encrypted MTProto, but a
subscription token travelling in that channel is a bearer credential: without a
pin, an on-path attacker could impersonate the relay, collect tokens and fake
"your subscription expired" screens. The app therefore learns the SHA-256 of the
relay certificate's public key during setup (verifying the chain properly at
that point) and enforces it natively afterwards.

Nothing is needed on the server beyond keeping the key stable (`--reuse-key`).

## Blocked hosts (host can't reach Telegram directly)

Some VPS providers block Telegram from the server itself. In that case route the
Telegram DC ranges through a VPN/gateway that can reach them (e.g. a `wg`/`tinc`
tunnel on the host), then switch the relay to host networking so it uses those
routes:

* In `docker-compose.yml`: comment out `ports:` and add `network_mode: host`.
* Add host routes for the Telegram CIDRs via your tunnel gateway, e.g.
  `ip route add 149.154.160.0/20 via <gw> dev <tun>` (and the other Telegram
  ranges: `91.105.192.0/23 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22
  91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 95.161.64.0/20 185.76.151.0/24`).

## Backups

Every subscription lives in the `relay-data` volume. Recreating the container
without it destroys all of them.

```bash
docker compose exec mtrelay python3 -c \
  "import sqlite3;sqlite3.connect('/data/relay.db').execute(\"VACUUM INTO '/data/backup.db'\")"
```

## What the operator can see

Worth being honest about, since this is a censorship-circumvention tool and the
logs are the largest deanonymisation risk if the machine is seized:

* token prefix, device id, byte counts, connection timing;
* the client's network at `/24` (v4) or `/48` (v6) granularity by default.

`LOG_IP=full` records exact addresses and is opt-in. Hashing full addresses is
**not** a safer middle ground: the IPv4 space is small enough that a hashed log
can be inverted by brute force in minutes. Consider an encrypted volume for
`/data` and keep log retention short.

The relay never sees who the Telegram user is — MTProto stays end-to-end
encrypted to Telegram — so identity here is the token, not an account.

## Tests

```bash
python3 -m unittest discover server/tests
```

Covers the happy path, expiry, revocation, device limits, tunnel whitelisting,
metering, and — most importantly — that unknown tokens and plain HTTP probes get
byte-identical cover-site treatment. No phone or Telegram account needed.

## Config reference (env)

See [`.env.example`](.env.example) for the full list with comments. The ones
that matter most:

| var | default | meaning |
|-----|---------|---------|
| `RELAY_LISTEN_HOST` / `RELAY_LISTEN_PORT` | `0.0.0.0` / `443` | bind address |
| `RELAY_CERT` / `RELAY_KEY` | `/certs/fullchain.pem` `/certs/privkey.pem` | TLS cert/key |
| `RELAY_DB` | `/data/relay.db` | subscriptions (put it on a volume) |
| `ALLOW_V1` | `1` | carry token-less clients (set `0` for a paid deployment) |
| `MASK_HOST` / `MASK_PORT` | – | cover-site backend |
| `ADMIN_UI` | `0` | serve the admin panel on a secret path |
| `RELAY_PUBLIC_HOST` / `RELAY_PUBLIC_PORT` | – / bind port | what setup codes tell clients to dial |
| `RENEW_HINT` | – | shown to a customer whose subscription lapsed |
| `DEVICE_GRACE_SEC` / `DEVICE_POLICY` | `180` / `strict` | device-slot behaviour |
| `LOG_IP` | `prefix` | `off` \| `prefix` \| `full` |
| `DC1`..`DC5`, `DC_PORT` | Telegram prod IPs / 443 | DC address overrides |
