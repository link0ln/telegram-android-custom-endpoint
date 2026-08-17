# Client — custom-endpoint Telegram for Android

A small set of changes to **[DrKLO/Telegram](https://github.com/DrKLO/Telegram)**
that make the official Android client connect to Telegram through your own
**real-TLS relay** instead of the built-in Fake-TLS MTProxy (which pattern-based
DPI blocks). Everything is entered by the user at setup — no credentials or
endpoints are baked in.

## What it does

* Adds a **Setup flow** (`ConfigActivity`), reachable at first launch and
  afterwards from its own **"Relay Setup"** launcher icon:
  1. one field taking either a setup code (`host[:port][@ip]|TOKEN|CHECK`) or,
     for a self-hosted relay, just an endpoint host — the code already carries
     the host, so which one you pasted is detected rather than asked;
     validated against the relay before anything is saved;
  2. the user's own `api_id` / `api_hash`, either entered by hand or read
     automatically from my.telegram.org in an in-app WebView tunnelled through
     the relay;
  3. a renewal screen when the subscription lapses.
* **The constraint the flow is built around:** my.telegram.org sends its
  confirmation code as a *Telegram message*, never by SMS, so creating an
  api_id needs an account already signed in somewhere else. That cannot be
  engineered away, so the copy says it before the user starts rather than after
  they are stuck, and there is a dedicated screen listing the ways out.
* The native transport (`tgnet`) is patched so that, when an endpoint is set,
  every datacenter resolves to `<endpoint>:443` and the socket performs a
  **genuine BoringSSL TLS handshake** (SNI = your host) instead of the stock
  Fake-TLS. The connect address is overridden at connect time, so a cached
  `tgnet.dat`, a `getConfig` response or a DC migration cannot route around the
  relay.
* Right after the handshake the client announces itself inside the TLS session:
  * with a subscription — a 39-byte v2 hello (magic, version, DC, token, device
    id), and it then **waits for the relay's 10-byte answer before handing the
    socket to tgnet**. Acknowledging earlier would let MTProto pour into a
    connection the relay is about to drop, and the subscription verdict has not
    arrived yet.
  * without one — the original 5-byte `TGR1<dcId>` header, so self-hosted relays
    keep working unchanged.
* MTProto stays end-to-end encrypted to Telegram throughout; the relay only ever
  sees TLS-wrapped ciphertext and which DC to forward to.
* If no endpoint is configured, the client behaves like normal Telegram.

## Certificate pinning

The native TLS client does **not** verify the relay's certificate chain. That was
harmless while the connection carried only end-to-end encrypted MTProto, but a
subscription token is a bearer credential: without a pin, an on-path attacker —
exactly the adversary this project exists to defeat — could impersonate the
relay, harvest tokens and fake "your subscription expired".

So `RelayClient` (plain Java, full chain and hostname verification) records the
SHA-256 of the relay certificate's public key during setup, and the native layer
enforces it on every connection afterwards. An empty pin disables the check,
which is the self-hosting default.

Renew the relay certificate with `--reuse-key`, or plan a pin rotation.

## Files

| | |
|-|-|
| `patches/custom-endpoint.patch` | multi-line changes to tgnet, the manifest and LaunchActivity |
| `apply.sh` | applies the patch, then a handful of count-checked regex edits, then copies the new files |
| `src/org/telegram/messenger/CustomConfig.java` | settings + `relay.cfg` writer |
| `src/org/telegram/messenger/ConfigActivity.java` | setup screen |
| `src/org/telegram/messenger/RelayClient.java` | Java speaker of the relay protocol; learns the pin |
| `src/org/telegram/messenger/DeviceId.java` | random per-install id, for the device limit |
| `src/org/telegram/messenger/RelayStatus.java` | watches the verdict native writes; opens the renewal screen |
| `src/org/telegram/messenger/LocalProxy.java` | loopback CONNECT proxy that carries the setup WebView through the relay |
| `src/org/telegram/messenger/MyTelegramExtractor.java` | reads api_id / api_hash off the my.telegram.org page |

### The WebView bridge

A WebView uses the system network stack, not tgnet, so it cannot use the native
relay transport — and on the networks this product is for, my.telegram.org is
precisely what is blocked. `LocalProxy` bridges the two: it listens on loopback,
speaks ordinary HTTP `CONNECT`, and carries each request to the relay as a
tunnel. `ProxyController` (androidx.webkit, added by `apply.sh`) points the
WebView at it.

Two things about that are deliberate. The proxy runs **only while the setup step
is on screen** — while it is up, any app on the device could reach the
whitelisted hosts through the customer's subscription. And the proxy override is
process-wide, so it is cleared on the way out; leaving it set would quietly
route every later WebView in the app through the relay.

Extraction scans **`innerText`, never HTML**: the login page carries a hidden
`random_hash` and the create-app form a hidden `hash`, both 32 hex characters
and indistinguishable from an api_hash in markup. Hidden input values never
appear in innerText, so reading text excludes them structurally instead of by
guesswork. The create-app form is prefilled but never auto-submitted — the user
presses the button, so nothing is created on their account unasked.

### Why some edits are not in the patch

Four one-line changes (linking `ssl`, blanking `BuildVars.APP_ID/APP_HASH`, and
two `api_id` call sites) live in `apply.sh` as regex substitutions instead of
patch hunks. They target unique strings and carry no diff context, so they
survive upstream refactoring that would break a hunk — and each asserts it
matched exactly once, so a moved target fails loudly instead of silently doing
nothing. `apply.sh --check` validates both the patch and those targets, which is
what the daily upstream watcher runs.

## Build

Prereqs: Android SDK (platform 35, build-tools 35.0.0), NDK `27.2.12479018`,
cmake 3.22+, JDK 17. BoringSSL `libssl.a` is already prebuilt inside DrKLO's tree
(`TMessagesProj/jni/boringssl/lib/<abi>/`); the patch just links it into `tgnet`.

```bash
# 1. check out the commit these patches were made against
#    (see TG_COMMIT in .github/workflows/build.yml)
git clone https://github.com/DrKLO/Telegram.git
cd Telegram && git checkout 9bcf3d2769c6d3f07105a992e5d9493e33ac3348 && cd ..

# 2. apply (use --check first to dry-run)
./apply.sh ./Telegram

# 3. build. Restrict abiFilters in TMessagesProj_App/build.gradle to
#    "arm64-v8a" to build ~4x faster if that is all you need.
cd Telegram
echo "sdk.dir=/path/to/android-sdk" > local.properties
./gradlew :TMessagesProj_App:assembleAfatDebug
# -> TMessagesProj_App/build/outputs/apk/afat/debug/app.apk
```

The debug build installs alongside the official app (`org.telegram.messenger.beta`).

## Debugging on a device

```bash
adb shell run-as org.telegram.messenger.beta cat files/relay.cfg   # what native will read
adb logcat -s tmessages                                            # tgnet, including relay status
```

`relay.cfg` is `key=value`, one per line (`v`, `ip`, `sni`, `token`, `dev`,
`pin`, `status`). Deleting the endpoint deletes the file, which returns the app
to behaving like stock Telegram.

To exercise the "subscription expired" path without waiting for one to lapse,
write the status file the native layer would have written:

```bash
adb shell run-as org.telegram.messenger.beta sh -c 'printf "status=1\nttl=0\n" > files/relay.status'
```

## Notes / TODO

* Upstream commits may move the anchor lines the patch targets; `apply.sh --check`
  tells you, and the hunks are small and marked with `// CUSTOM:`.
* Changing the endpoint after login should also clear the saved DC config
  (`files/**/tgnet.dat`). The connect-time address override makes this mostly
  cosmetic now, but the stale file is still confusing when debugging.
* The endpoint address is re-resolved by `CustomConfig.refreshEndpointIp()`;
  because native reads `relay.cfg` only during `init()`, a changed address takes
  effect on the next process start rather than immediately.
* `ConfigActivity` is exported so it can have a launcher icon, so it must treat
  its extras as a hint and never act destructively on one without a confirming
  tap.
* You may want to hide the "Test Backend" checkbox in `LoginActivity` (its test
  DCs are not routed through the relay) and rename the package for a real release.
* The headless fallback for my.telegram.org (driving the forms over the tunnel
  without a WebView) is not implemented: manual entry covers the same case, and
  a scripted login is both brittle and the sort of thing Telegram treats as
  abuse.
