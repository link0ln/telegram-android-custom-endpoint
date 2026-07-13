# Server — real-TLS relay

A tiny stdlib-only Python relay (`mtrelay.py`) that terminates **genuine TLS** on
`443` and forwards the custom client's MTProto stream to the real Telegram
datacenters. On the wire the connection is indistinguishable from ordinary HTTPS
to your domain, so pattern-based DPI (which detects Telegram's own Fake-TLS
proxies) has nothing to match on.

```
custom client --REAL TLS(your-domain:443)--> mtrelay --> Telegram DC (1..5)
                                                 └── other traffic --> optional cover site
```

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

(Or symlink the `live/<domain>/` directory to `./certs`. Renew as usual and
`docker compose restart mtrelay`.)

## 2. Run

```bash
docker compose up -d --build
docker compose logs -f mtrelay
```

You should see `mtrelay listening on 0.0.0.0:443`. When a client connects you'll
see `PROXY dc=2 -> 149.154.167.51:443` lines.

## 3. Configure the client

In the app's first-run **Setup** screen enter your `api_id`, `api_hash`
(from https://my.telegram.org) and the **endpoint host** = your domain
(`relay.example.com`).

## Optional: cover site (probe resistance)

Set `MASK_HOST` / `MASK_PORT` in `docker-compose.yml` to a real website you host.
Any non-proxy connection (a browser, a DPI active probe hitting `https://your-domain/`)
is then transparently proxied to that site, so the endpoint serves genuine content.

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

## Config reference (env)

| var | default | meaning |
|-----|---------|---------|
| `RELAY_LISTEN_HOST` | `0.0.0.0` | bind address |
| `RELAY_LISTEN_PORT` | `443` | bind port |
| `RELAY_CERT` / `RELAY_KEY` | `/certs/fullchain.pem` `/certs/privkey.pem` | TLS cert/key |
| `MASK_HOST` / `MASK_PORT` | – | optional cover-site backend |
| `DC1`..`DC5`, `DC_PORT` | Telegram prod IPs / 443 | DC address overrides |
