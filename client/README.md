# Client — custom-endpoint Telegram for Android

A small set of changes to **[DrKLO/Telegram](https://github.com/DrKLO/Telegram)**
that make the official Android client connect to Telegram through your own
**real-TLS relay** instead of the built-in Fake-TLS MTProxy (which pattern-based
DPI blocks). Everything is entered by the user at first launch — no credentials
or endpoints are baked in.

## What it does

* Adds a **first-run Setup screen** (`ConfigActivity`) with three fields:
  `api_id`, `api_hash`, and the **relay endpoint host**. Stored in
  `SharedPreferences` via `CustomConfig`.
* The native transport (`tgnet`) is patched so that, when an endpoint is set, all
  datacenters point at `<endpoint>:443` and the socket performs a **genuine
  BoringSSL TLS handshake** (SNI = your host) instead of the stock Fake-TLS. Right
  after the handshake it sends a 5-byte routing header `TGR1<dcId>` so the relay
  knows which DC to forward to. MTProto stays end-to-end encrypted to the DC.
* `api_id` / `api_hash` are read from settings at login (`auth.sendCode`) and at
  connection init; the bundled `BuildVars.APP_ID/APP_HASH` are blanked.
* If no endpoint is configured, the client behaves like normal Telegram
  (connects directly to the real DCs).

## Files

| | |
|-|-|
| `patches/custom-endpoint.patch` | changes to existing tgnet / UI / manifest / gradle files |
| `src/org/telegram/messenger/CustomConfig.java` | settings helper (new file) |
| `src/org/telegram/messenger/ConfigActivity.java` | first-run setup screen (new file) |

## Build

Prereqs: Android SDK (platform 35, build-tools 35.0.0), NDK `27.2.12479018`,
cmake 3.22+, JDK 17. BoringSSL `libssl.a` is already prebuilt inside DrKLO's tree
(`TMessagesProj/jni/boringssl/lib/<abi>/`); the patch just links it into `tgnet`.

```bash
# 1. check out the exact upstream commit these patches were made against
git clone https://github.com/DrKLO/Telegram.git
cd Telegram
git checkout 9b50143d8896d255d03155598937e4f3e28afd86     # base commit
cd ..

# 2. apply
./apply.sh ./Telegram

# 3. build (debug, universal). Restrict ABIs in TMessagesProj_App/build.gradle
#    (abiFilters) to just "arm64-v8a" to build ~4x faster if you only need arm64.
cd Telegram
echo "sdk.dir=/path/to/android-sdk" > local.properties
./gradlew :TMessagesProj_App:assembleAfatDebug
# -> TMessagesProj_App/build/outputs/apk/afat/debug/app.apk
```

The debug build installs alongside the official app (`org.telegram.messenger.beta`).

## Notes / TODO

* Newer upstream commits may move the anchor lines the patch targets; re-base if
  `git apply` fails, or apply the hunks by hand (they are small and clearly
  marked with `// CUSTOM:` comments).
* Changing the endpoint after first login should also clear the saved DC config
  (`files/**/tgnet.dat`) so the new relay addresses take effect — otherwise the
  client keeps the previously-cached datacenter addresses. (Planned improvement:
  do this automatically in `ConfigActivity` on save.)
* You may want to hide the "Test Backend" checkbox in `LoginActivity` (its test
  DCs are not routed through the relay) and rename the package for a real release.
