# telegram-android-custom-endpoint

[![build-apk](https://github.com/link0ln/telegram-android-custom-endpoint/actions/workflows/build.yml/badge.svg)](https://github.com/link0ln/telegram-android-custom-endpoint/actions/workflows/build.yml)

Route the official **Telegram for Android** through your own server over
**genuine TLS**, so it survives pattern-based DPI that blocks Telegram's built-in
Fake-TLS MTProxy.

## Why

Telegram's MTProxy (even in Fake-TLS `ee` mode) answers a TLS `ClientHello` with a
minimal, non-standard flight. Sophisticated DPI (e.g. Russia's TSPU on some mobile
carriers) can tell it apart from a real TLS server and black-holes it — while
ordinary HTTPS to the same IP passes fine. There is no way to fix this from the
proxy side, because Telegram's proxy protocol never performs a real TLS handshake.

This project sidesteps it: a lightly patched Telegram client opens a **real TLS
connection** (BoringSSL, real handshake, your certificate) to a small relay you
run. On the wire it is indistinguishable from normal HTTPS to your domain, so
there is nothing for the DPI to match. The relay reads a tiny routing header and
forwards the still-end-to-end-encrypted MTProto to the real Telegram DCs.

```
 Telegram app (patched)                          your server                Telegram
 ┌───────────────────┐   REAL TLS (:443,        ┌──────────┐   MTProto      ┌────────┐
 │ genuine BoringSSL  │──  SNI = your domain) ──▶│ mtrelay  │──────────────▶ │ DC 1..5 │
 │ TLS + TGR1<dc> hdr │                          │ (TLS term│                └────────┘
 └───────────────────┘                          │ + route) │
                                                 │  else ──▶ optional cover website
                                                 └──────────┘
```

The MTProto payload stays end-to-end encrypted between the app and Telegram — the
relay only sees TLS-wrapped, already-encrypted bytes and which DC to forward to.

## Layout

* [`server/`](server/) — the relay: `mtrelay.py` + `Dockerfile` + `docker-compose.yml`.
  Terminates TLS on 443, routes to the Telegram DCs, optionally masks other traffic
  to a cover site. **stdlib only, no dependencies.**
* [`client/`](client/) — a patch + two new files for
  [DrKLO/Telegram](https://github.com/DrKLO/Telegram): a first-run **Setup** screen
  (`api_id`, `api_hash`, endpoint host) and the native real-TLS transport.

## Quick start

1. **Server:** point a domain at your VPS, get a TLS cert, `docker compose up -d`
   in `server/` (see [server/README.md](server/README.md)).
2. **Client:** apply the patch to a DrKLO/Telegram checkout and build the APK
   (see [client/README.md](client/README.md)).
3. Install the APK, and on first launch enter your `api_id` + `api_hash`
   (from https://my.telegram.org) and your relay's domain.

**Prebuilt APK:** CI ([`.github/workflows/build.yml`](.github/workflows/build.yml))
builds the client automatically — grab the artifact from the **Actions** tab, or a
tagged build from **Releases** (push a `v*` tag to cut one). It's debug-signed and
you still enter your own `api_id`/`api_hash`/endpoint on first launch.

**Staying current with upstream:** the client is a patch on top of
[DrKLO/Telegram](https://github.com/DrKLO/Telegram) **master**, pinned to a specific
commit (`TG_COMMIT` in the build workflow). DrKLO's GitHub releases/tags are stale
(last: 11.4.2, Nov 2024) — it ships versions as squashed `update to X.Y.Z` commits
straight to `master`, so master HEAD *is* the latest version. A scheduled job
([`.github/workflows/upstream-watch.yml`](.github/workflows/upstream-watch.yml))
polls master HEAD daily; when it moves past the pinned commit it dry-runs the patch
and opens a tracking **issue**: if the patch still applies it also builds an APK
artifact from that master commit; if upstream reworked the native transport enough
that the patch no longer applies, the issue flags it for a manual rebase. Promoting
any build to a public **Release** is always a manual `v*` tag, so an unattended
build is never published on its own.

## Status

Working end to end (login + chats + media) on a mobile network where the ordinary
MTProxy was blocked. This is a proof-of-concept / self-host tool, not a polished
product — see the TODO in [client/README.md](client/README.md).

## Legal

The client portion is derived from **DrKLO/Telegram**, licensed under the
**GNU GPL v2 or later**; this repository inherits that license (see `LICENSE`).
You are responsible for your own `api_id`/`api_hash` (per Telegram's terms) and
for how you operate the relay. Nothing here weakens Telegram's end-to-end MTProto
encryption.
