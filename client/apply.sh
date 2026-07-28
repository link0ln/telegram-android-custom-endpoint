#!/usr/bin/env bash
# Apply the custom-endpoint changes onto a DrKLO/Telegram checkout.
#
#   git clone https://github.com/DrKLO/Telegram.git
#   (cd Telegram && git checkout <the commit in .github/workflows/build.yml>)
#   ./apply.sh ./Telegram
#
# Use --check to dry-run everything (patch + in-place edits) without touching
# the tree; that is what the upstream watcher runs against new DrKLO releases.
#
# The change set comes in three parts:
#   1. patches/custom-endpoint.patch  - multi-line additions to tgnet and friends
#   2. src/...                        - new files, copied in verbatim
#   3. the subst() calls below        - one-line edits done by regex instead of
#      patch hunks. These target unique strings and carry no diff context, so
#      they survive upstream refactoring that would break a patch hunk. Each one
#      asserts it matched exactly once and fails loudly otherwise.
set -euo pipefail

CHECK=0
if [ "${1:-}" = "--check" ]; then CHECK=1; shift; fi

TG="${1:?usage: ./apply.sh [--check] /path/to/Telegram-checkout}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$TG/TMessagesProj/jni/tgnet" ]; then
    echo "error: '$TG' does not look like a DrKLO/Telegram checkout" >&2
    exit 1
fi

# subst <relative-path> <before-ere> <after-ere> <sed-script> <label>
#   before-ere must match exactly once on a pristine tree.
#   after-ere  is how we recognise an already-edited tree (idempotency).
subst() {
    local rel="$1" before="$2" after="$3" script="$4" label="$5"
    local f="$TG/$rel" nb na
    if [ ! -f "$f" ]; then
        echo "error: [$label] missing file: $rel" >&2
        exit 1
    fi
    nb=$(grep -cE "$before" "$f" || true)
    na=$(grep -cE "$after" "$f" || true)
    if [ "$nb" -eq 0 ] && [ "$na" -ge 1 ]; then
        echo "   = $label (already applied)"
        return 0
    fi
    if [ "$nb" -ne 1 ]; then
        echo "error: [$label] expected exactly 1 match for /$before/ in $rel, found $nb" >&2
        echo "       upstream changed this code - the edit needs to be re-targeted" >&2
        exit 1
    fi
    if [ "$CHECK" -eq 1 ]; then
        echo "   ok $label"
        return 0
    fi
    sed -i -e "$script" "$f"
    na=$(grep -cE "$after" "$f" || true)
    if [ "$na" -lt 1 ]; then
        echo "error: [$label] edit did not take effect in $rel" >&2
        exit 1
    fi
    echo "   + $label"
}

apply_edits() {
    # tgnet must link BoringSSL's libssl (prebuilt in the tree) for the real-TLS transport
    subst "TMessagesProj/jni/CMakeLists.txt" \
        '^        crypto\)$' \
        '^        ssl crypto\)$' \
        '/^target_link_libraries(tgnet$/{n;s/^        crypto)$/        ssl crypto)/;}' \
        "CMakeLists: link ssl into tgnet"

    # the app ships no api credentials of its own - the user supplies them at setup
    subst "TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java" \
        'public static int APP_ID = [1-9][0-9]*;' \
        'public static int APP_ID = 0;' \
        's/public static int APP_ID = [0-9]*;/public static int APP_ID = 0;/' \
        "BuildVars: blank APP_ID"

    subst "TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java" \
        'public static String APP_HASH = "[0-9a-f]+";' \
        'public static String APP_HASH = "";' \
        's/public static String APP_HASH = "[0-9a-f]*";/public static String APP_HASH = "";/' \
        "BuildVars: blank APP_HASH"

    subst "TMessagesProj/src/main/java/org/telegram/ui/LoginActivity.java" \
        'sendCode\.api_hash = BuildVars\.APP_HASH;' \
        'sendCode\.api_hash = org\.telegram\.messenger\.CustomConfig\.getApiHash\(\);' \
        's/sendCode\.api_hash = BuildVars\.APP_HASH;/sendCode.api_hash = org.telegram.messenger.CustomConfig.getApiHash();/' \
        "LoginActivity: api_hash from user config"

    subst "TMessagesProj/src/main/java/org/telegram/ui/LoginActivity.java" \
        'sendCode\.api_id = BuildVars\.APP_ID;' \
        'sendCode\.api_id = org\.telegram\.messenger\.CustomConfig\.getApiId\(\);' \
        's/sendCode\.api_id = BuildVars\.APP_ID;/sendCode.api_id = org.telegram.messenger.CustomConfig.getApiId();/' \
        "LoginActivity: api_id from user config"

    subst "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java" \
        'TLRPC\.LAYER, BuildVars\.APP_ID,' \
        'TLRPC\.LAYER, org\.telegram\.messenger\.CustomConfig\.getApiId\(\),' \
        's/TLRPC\.LAYER, BuildVars\.APP_ID,/TLRPC.LAYER, org.telegram.messenger.CustomConfig.getApiId(),/' \
        "ConnectionsManager: api_id from user config"

    # The setup WebView has to reach my.telegram.org through the relay, and the
    # only supported way to point a WebView at a proxy is ProxyController, which
    # lives in androidx.webkit. Appended here rather than patched so a gradle
    # reshuffle upstream cannot break it.
    subst "TMessagesProj/build.gradle" \
        '^dependencies \{$' \
        'androidx\.webkit:webkit' \
        "/^dependencies {\$/a\\    implementation 'androidx.webkit:webkit:1.12.1'" \
        "build.gradle: androidx.webkit for the setup WebView"

    # relay.cfg has to exist before native init() reads it
    subst "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java" \
        '^[[:space:]]*native_init\(currentAccount, version' \
        'CustomConfig\.writeRelayFile\(configPath\);' \
        's|^\([[:space:]]*\)native_init(currentAccount, version|\1org.telegram.messenger.CustomConfig.writeRelayFile(configPath);   // CUSTOM: relay.cfg must exist before native init() reads it\n\1org.telegram.messenger.RelayStatus.start(configPath);            // CUSTOM: watch for the subscription verdict native writes back\n\1native_init(currentAccount, version|' \
        "ConnectionsManager: write relay.cfg before native_init"
}

if [ "$CHECK" -eq 1 ]; then
    echo ">> dry-run: checking patch applies against $TG"
    git -C "$TG" apply --check --whitespace=nowarn "$HERE/patches/custom-endpoint.patch"
    echo ">> dry-run: checking in-place edit targets"
    apply_edits
    echo ">> OK: patch applies cleanly and every edit target was found"
    exit 0
fi

echo ">> applying patch"
git -C "$TG" apply --whitespace=nowarn "$HERE/patches/custom-endpoint.patch"

echo ">> applying in-place edits"
apply_edits

echo ">> copying new files"
# copy the whole tree, so adding a class never means touching this script
cp -r "$HERE/src/org" "$TG/TMessagesProj/src/main/java/"
find "$HERE/src" -name '*.java' | sed "s|$HERE/src/|   + |"

echo ">> done. Build with:"
echo "   cd $TG && ./gradlew :TMessagesProj_App:assembleAfatDebug"
