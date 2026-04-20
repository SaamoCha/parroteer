# Parroteer

Automated browser fingerprint monitoring and parrot drift detection for
[utls](https://github.com/refraction-networking/utls) and
[uquic](https://github.com/refraction-networking/uquic).

Runs daily on GitHub Actions. Captures real browser TLS fingerprints via
Selenium, normalizes them, compares against utls parrots, and opens a
GitHub Issue when a parrot falls out of sync with its real browser.

## Why

utls/uquic maintain hand-crafted "parrot" presets that mimic real browser
fingerprints. When a browser changes cipher suites, extensions, or QUIC
transport parameters — whether through a version bump or a silent
server-side rollout — the parrots go stale. Today this is noticed manually,
sometimes weeks late. Parroteer closes that gap.

## How It Works

```
Daily cron (UTC 06:00) or manual trigger
  │
  ├─ 1. Update utls ── go get utls@main (always test latest commit)
  │
  ├─ 2. Capture ── launch real browsers (Selenium + system binaries)
  │                 + utls parrots (Go, via cmd/utls-capture)
  │                 → hit tls.browserleaks.com reflector
  │                 → get full TLS ClientHello JSON
  │
  ├─ 3. Normalize ── replace GREASE values with sentinel (preserve position)
  │                   sort randomized extension order (preserve GREASE bookends)
  │                   extract supported_versions, key_shares, sig_algs from extensions
  │                   → produce stable structural fingerprint
  │
  ├─ 4. Diff ── compare browser vs baseline (fingerprint drift detection)
  │             compare browser vs utls parrot (parrot accuracy check)
  │
  └─ 5. Notify ── known diff unchanged: log only, no Issue
                   new or changed diff: open GitHub Issue
                   baseline updated: commit back to repo
```

## Architecture

```
parroteer/
├── .github/workflows/
│   └── fingerprint-watch.yml  # daily cron + manual dispatch
│
├── cmd/
│   ├── utls-capture/          # Go: capture utls parrot fingerprint via reflector
│   ├── ch-compare/            # Go: compare ClientHello structures
│   └── ch-inspect/            # Go: inspect ClientHello details
│
├── src/
│   ├── capture.ts             # Selenium: launch browser, visit reflector, get JSON
│   ├── normalize.ts           # strip noise, preserve GREASE positions, extract fields
│   ├── report.ts              # structural diff + format Issue body
│   └── run.ts                 # entry point: capture → normalize → diff → notify
│
├── fixtures/
│   ├── baselines/             # last known browser fingerprints (committed by CI)
│   └── known-diffs/           # last seen utls-vs-browser diffs (dedup mechanism)
│
├── reports/                   # diff reports (gitignored, uploaded as CI artifacts)
├── scripts/
│   └── install-browsers.sh    # install Chrome, Edge, Firefox on Ubuntu
│
├── go.mod / go.sum            # Go deps (utls, auto-updated to latest commit)
├── package.json               # Node deps (selenium-webdriver, tsx)
└── tsconfig.json
```

## Reflector

Uses [tls.browserleaks.com](https://tls.browserleaks.com/) (root endpoint,
not `/json`). The root endpoint returns a full `tls` object with per-extension
detail:

- `tls.cipher_suites` — `[{id, name}, ...]` with GREASE entries
- `tls.extensions` — `[{id, name, data}, ...]` with nested fields:
  - ext 43 `supported_versions` — version list
  - ext 51 `key_share` — group IDs and key lengths
  - ext 13 `signature_algorithms` — full sig alg list
  - ext 16 `alpn` — protocol list

The `/json` endpoint only returns ja3/ja4 summaries and lacks these details.

## GREASE Handling

GREASE (RFC 8701) values are **not stripped** — their positions are preserved
as sentinel values (`-1`). This matters for fingerprint mimicking because:

- Chrome always places GREASE at the start of cipher suites
- Chrome wraps extensions with GREASE at first and last position
- Chrome adds GREASE to supported_groups, supported_versions, key_shares
- Firefox does not use GREASE at all

If a browser changes its GREASE placement strategy, parroteer detects it.

Chrome randomizes extension order per-connection, so the normalizer peels
off GREASE bookends, sorts the interior, then re-attaches them.

## Notification Dedup

utls-vs-browser diffs are saved to `fixtures/known-diffs/`. A hash of the
diff result is compared against the last known hash:

- **Same hash** → known diff, skip notification
- **Different hash** → new or changed diff, open Issue
- **Parrot now matches** → clear known diff record

This prevents daily duplicate Issues for the same stale parrot.

## utls Version

The CI workflow runs `go get github.com/refraction-networking/utls@main`
before each capture. This means:

- Every run tests against the **latest utls commit** on main
- If someone pushes a parrot fix to utls, the next daily run will pick it up
- `go.mod` and `go.sum` are committed back, so you can track which utls
  version each run tested against

## Why Selenium

Selenium always drives the **real browser binary** installed on the system.
No patched or bundled browsers. This matters because:

- Playwright's Firefox is a patched build — TLS fingerprint may differ
  from the real Firefox release
- Playwright's WebKit is not Safari — Safari's TLS comes from Apple's
  SecureTransport, unreproducible on Linux
- Selenium uses the system-installed browser directly, so the captured
  fingerprint is exactly what a real user would produce

Driver management is handled by selenium-manager (built into Selenium v4+).

## Browser Coverage

### Current (GitHub Actions ubuntu-latest)

| Browser | Binary | Install |
|---|---|---|
| Chrome Stable | `/usr/bin/google-chrome-stable` | `scripts/install-browsers.sh` |
| Edge Stable | `/usr/bin/microsoft-edge-stable` | `scripts/install-browsers.sh` |
| Firefox Stable | `/usr/bin/firefox` | `scripts/install-browsers.sh` |

### Planned

| Browser | Notes |
|---|---|
| Chrome Beta | Same install script, not yet enabled |
| Firefox Nightly | Manual download from Mozilla |
| Safari | Requires macOS runner + safaridriver |

## Normalization Fields

| Field | Source | GREASE |
|---|---|---|
| cipher_suites | `tls.cipher_suites[].id` | preserved |
| extensions | `tls.extensions[].id` | bookends preserved, interior sorted |
| supported_groups | ext 10 `named_group_list` | preserved |
| supported_versions | ext 43 `versions` | preserved |
| key_share_groups | ext 51 `client_shares[].group.id` | preserved |
| signature_algorithms | ext 13 `supported_signature_algorithms` | N/A |
| alpn | ext 16 `protocol_name_list` | N/A |
| ec_point_formats | ext 11 `ec_point_format_list` | N/A |
| psk_key_exchange_mode | ext 45 `ke_modes` | N/A |

Fallback: if `tls` object is absent (e.g. `/json` endpoint), parses from
`ja3_text` + `ja4_r` with reduced coverage (no GREASE, no versions/key_shares).

## Usage

### Manual run (local)

```bash
# Install browsers (Ubuntu)
bash scripts/install-browsers.sh

# Install deps
npm ci

# Run all browsers
npx tsx src/run.ts

# Run single browser
npx tsx src/run.ts --browser chrome-stable

# Run with GitHub Issue notification
npx tsx src/run.ts --notify
```

### GitHub Actions

The workflow runs automatically at UTC 06:00 daily. To trigger manually:

1. Go to **Actions** → **Fingerprint Watch**
2. Click **Run workflow**
3. Optionally specify a single browser or disable notifications

### Normalize a raw capture

```bash
npx tsx src/normalize.ts fixtures/captures/chrome-stable-raw.json
```

## Development Roadmap

### Phase 1: Capture + Detect — done

- [x] Selenium capture for Chrome, Edge, Firefox
- [x] Normalization with GREASE position preservation
- [x] Structural diff (field-level added/removed/changed)
- [x] utls parrot vs real browser comparison
- [x] GitHub Actions daily cron
- [x] Known-diff dedup (no duplicate Issues)
- [x] Auto-update utls to latest commit

### Phase 2: Parrot Generation + QUIC

- [ ] ClientHello → ClientHelloSpec Go code generator
- [ ] Replay check (gen spec → connect to reflector → compare)
- [ ] Self-hosted reflector for QUIC Alt-Svc
- [ ] QUIC Initial capture + QUICSpec generator
- [ ] On successful replay: open draft PR with generated Go code

### Future

- [ ] Safari via macOS runner
- [ ] Chrome Beta / Firefox Nightly
- [ ] iOS Safari via Xcode simulator

## Known Challenges

**Headless mode matters:** Chrome's `--headless=new` and Firefox's `-headless`
produce the same TLS fingerprint as headed mode. Legacy `--headless` (Chrome)
does not.

**QUIC requires two visits:** Browsers use TCP on first connection. The
reflector must send `Alt-Svc` header so the browser upgrades to QUIC on the
second visit. Only relevant in Phase 2.

**Safari requires macOS:** Safari's TLS fingerprint comes from Apple's
SecureTransport, which only exists on macOS/iOS.

## License

TBD
