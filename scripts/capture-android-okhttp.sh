#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_PROJECT_DIR="$ROOT_DIR/android/okhttp-capture"
CAPTURES_DIR="$ROOT_DIR/fixtures/captures"
DATE="${PARROTEER_CAPTURE_DATE:-$(date -u +%F)}"
DATED_CAPTURE="$CAPTURES_DIR/android-okhttp-$DATE.json"
LATEST_CAPTURE="$CAPTURES_DIR/android-okhttp-latest.json"

mkdir -p "$CAPTURES_DIR"

gradle -p "$ANDROID_PROJECT_DIR" \
  :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.parroteer.android.OkHttpCaptureTest

adb exec-out run-as com.parroteer.android cat files/android-okhttp.json > "$DATED_CAPTURE"
test -s "$DATED_CAPTURE"
cp "$DATED_CAPTURE" "$LATEST_CAPTURE"

echo "Android OkHttp capture saved to $DATED_CAPTURE"
