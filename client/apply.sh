#!/usr/bin/env bash
# Apply the custom-endpoint changes onto a DrKLO/Telegram checkout.
#
#   git clone https://github.com/DrKLO/Telegram.git
#   (cd Telegram && git checkout 9b50143d8896d255d03155598937e4f3e28afd86)
#   ./apply.sh ./Telegram
#
set -euo pipefail

TG="${1:?usage: ./apply.sh /path/to/Telegram-checkout}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$TG/TMessagesProj/jni/tgnet" ]; then
    echo "error: '$TG' does not look like a DrKLO/Telegram checkout" >&2
    exit 1
fi

echo ">> applying patch"
git -C "$TG" apply --whitespace=nowarn "$HERE/patches/custom-endpoint.patch"

echo ">> copying new files"
DEST="$TG/TMessagesProj/src/main/java/org/telegram/messenger"
cp "$HERE/src/org/telegram/messenger/CustomConfig.java"   "$DEST/"
cp "$HERE/src/org/telegram/messenger/ConfigActivity.java" "$DEST/"

echo ">> done. Build with:"
echo "   cd $TG && ./gradlew :TMessagesProj_App:assembleAfatDebug"
