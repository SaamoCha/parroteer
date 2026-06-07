#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_PROJECT_DIR="$ROOT_DIR/android/okhttp-capture"
CAPTURES_DIR="$ROOT_DIR/fixtures/captures"
APP_ID="com.parroteer.android"
TEST_ID="$APP_ID.test"
RUNNER="androidx.test.runner.AndroidJUnitRunner"
DATE="${PARROTEER_CAPTURE_DATE:-$(date -u +%F)}"
DATED_CAPTURE="$CAPTURES_DIR/android-okhttp-$DATE.json"
LATEST_CAPTURE="$CAPTURES_DIR/android-okhttp-latest.json"
INSTRUMENT_LOG="$(mktemp)"

mkdir -p "$CAPTURES_DIR"
trap 'rm -f "$INSTRUMENT_LOG"' EXIT

gradle -p "$ANDROID_PROJECT_DIR" \
  :app:installDebug \
  :app:installDebugAndroidTest

adb shell run-as "$APP_ID" rm -f files/android-okhttp.json >/dev/null 2>&1 || true
adb shell am instrument -w -r \
  -e class com.parroteer.android.OkHttpCaptureTest \
  "$TEST_ID/$RUNNER" \
  2>&1 | tee "$INSTRUMENT_LOG"

if grep -q "FAILURES!!!\\|INSTRUMENTATION_RESULT: shortMsg=" "$INSTRUMENT_LOG"; then
  echo "Android instrumentation test failed." >&2
  exit 1
fi

if ! grep -q "INSTRUMENTATION_CODE: -1" "$INSTRUMENT_LOG"; then
  echo "Android instrumentation did not report a successful completion code." >&2
  exit 1
fi

adb exec-out run-as "$APP_ID" cat files/android-okhttp.json > "$DATED_CAPTURE"
test -s "$DATED_CAPTURE"
node -e '
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!data.tls || !Array.isArray(data.tls.cipher_suites) || !Array.isArray(data.tls.extensions)) {
  throw new Error("BrowserLeaks response is missing detailed tls.cipher_suites/tls.extensions arrays");
}
' "$DATED_CAPTURE"
cp "$DATED_CAPTURE" "$LATEST_CAPTURE"

echo "Android OkHttp capture saved to $DATED_CAPTURE"
