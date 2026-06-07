#!/usr/bin/env bash
set -euo pipefail

bash scripts/capture-android-okhttp.sh

args=(--browser android-okhttp)
if [ "${PARROTEER_NOTIFY:-false}" = "true" ] || [ "${GITHUB_EVENT_NAME:-}" = "schedule" ]; then
  args+=(--notify)
fi

npx tsx src/run.ts "${args[@]}"
