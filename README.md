# Parroteer

Automated browser fingerprint monitoring and parrot generation pipeline for
[utls](https://github.com/refraction-networking/utls) and
[uquic](https://github.com/refraction-networking/uquic).

Captures real browser TLS/QUIC fingerprints, detects structural changes, and
generates candidate parrot updates as draft PRs.

## Why

utls/uquic maintain hand-crafted "parrot" presets that mimic real browser
fingerprints. When a browser changes cipher suites, extensions, or QUIC
transport parameters — whether through a version bump or a silent
server-side rollout — the parrots go stale. Today this is noticed manually,
sometimes weeks late. Parroteer closes that gap.

## How It Works

```
cron / manual trigger
  │
  ├─ 1. Capture ── launch real browser (Selenium + real binary)
  │                 → hit tlsfingerprint.io (public reflector)
  │                 → get structured TLS ClientHello JSON
  │
  ├─ 2. Normalize ── strip GREASE values, random, session ID
  │                   → produce stable structural fingerprint
  │
  ├─ 3. Diff ── compare against baseline (last known fingerprint)
  │             → changed or not?
  │
  ├─ 4. Generate ── if structure changed:
  │                  → produce utls ClientHelloSpec (Go code)
  │                  → produce uquic QUICSpec candidate (Initial Packet only)
  │
  └─ 5. Notify ── no change: log only
                   changed: open GitHub Issue
                   changed + generator passes replay: open draft PR
```

## Architecture

```
parroteer/
├── .github/
│   └── workflows/
│       └── fingerprint-watch.yml    # cron + manual dispatch (optional)
│
├── src/
│   ├── capture.ts          # Selenium: launch browser, visit reflector
│   ├── normalize.ts        # strip noise, produce stable fingerprint
│   ├── diff.ts             # structural diff, report generation
│   ├── report.ts           # format Issue body
│   └── run.ts              # entry point: capture → normalize → diff → notify
│
├── fixtures/
│   └── baselines/          # last known normalized fingerprints
│       ├── chrome-stable.json
│       ├── chrome-beta.json
│       ├── msedge-stable.json
│       ├── firefox-stable.json
│       └── firefox-nightly.json
│
├── reports/                # diff reports (gitignore)
│
├── scripts/
│   └── install-browsers.sh # install Chrome, Edge, Firefox + drivers
│
├── package.json
├── tsconfig.json
└── README.md
```

## Reflector

Uses [tlsfingerprint.io](https://tlsfingerprint.io) — a public instance of
[clienthellod](https://github.com/gaukas/clienthellod). The browser visits
this URL and gets back a JSON representation of its own TLS ClientHello.

No self-hosted reflector needed for TLS fingerprinting. Self-hosting only
becomes necessary for QUIC capture (Phase 2+), because the reflector needs
to advertise `Alt-Svc` to trigger browser QUIC upgrade.

## Why Selenium

Selenium always drives the **real browser binary** installed on the system.
No patched or bundled browsers. This matters because:

- Playwright's Firefox is a patched build — TLS fingerprint may differ
  from the real Firefox release
- Playwright's WebKit is not Safari — Safari's TLS comes from Apple's
  SecureTransport, unreproducible on Linux
- Selenium uses the system-installed browser directly, so the captured
  fingerprint is exactly what a real user would produce

Driver management is handled by selenium-manager (built into Selenium v4+),
which auto-downloads the correct chromedriver/geckodriver version.

## Browser Coverage

### Phase 1 (Linux VPS)

| Browser | Binary | Driver | Install |
|---|---|---|---|
| Chrome Stable | `/usr/bin/google-chrome-stable` | chromedriver (auto) | `apt install google-chrome-stable` |
| Chrome Beta | `/usr/bin/google-chrome-beta` | chromedriver (auto) | `apt install google-chrome-beta` |
| Edge Stable | `/usr/bin/microsoft-edge-stable` | msedgedriver (auto) | `apt install microsoft-edge-stable` |
| Firefox Stable | `/usr/bin/firefox` | geckodriver (auto) | `apt install firefox` |
| Firefox Nightly | `/opt/firefox-nightly/firefox` | geckodriver (auto) | download from Mozilla |

### Future (requires macOS)

| Browser | Notes |
|---|---|
| Safari | safaridriver is built into macOS. GitHub Actions macOS runner or real Mac. |
| iOS Safari | real device or Xcode simulator |

## Normalization Rules

### TLS — keep:
- Cipher suites (order + values)
- Extension set and order
- Supported versions
- Key shares (groups, not values)
- ALPN / ALPS
- Signature algorithms
- Padding rules

### TLS — discard:
- Random bytes
- Session ID
- GREASE specific values (replace with placeholder)

## Generation Criteria

A generated parrot is only promoted to draft PR if:

1. TLS structural diff is fully explainable
2. Generated `ClientHelloSpec` compiles
3. Replay with new spec against reflector matches real browser fingerprint
4. Any ECH / token / PSK / retry anomaly → downgrade to Issue, no code change

## Development Plan

### Phase 1: Capture + Detect (Chrome + Edge + Firefox)

#### 1.1 Project scaffold

- [ ] `npm init`
- [ ] Install deps: `selenium-webdriver`, `typescript`, `tsx`
- [ ] Create `tsconfig.json`
- [ ] Create directory structure: `src/`, `fixtures/baselines/`, `reports/`
- [ ] Verify: `npx tsx --version` runs

Deliverable: empty project that compiles TypeScript.

#### 1.2 Capture one browser (Chrome Stable)

Prove the concept: launch real Chrome, hit reflector, get JSON back.

- [ ] Install Chrome Stable: `apt install google-chrome-stable`
- [ ] Verify it runs headless: `google-chrome-stable --headless=new --dump-dom about:blank`
- [ ] Create `src/capture.ts`:
      - Hardcode Chrome Stable for now
      - `chrome.Options` with `--headless=new`
      - Set binary: `/usr/bin/google-chrome-stable`
      - Navigate to `https://tlsfingerprint.io/tls`
      - Read page body → parse JSON → print to stdout
      - Quit driver
- [ ] Run: `npx tsx src/capture.ts`
- [ ] Verify output is valid ClientHello JSON with cipher suites, extensions, etc.
- [ ] Save output to `fixtures/captures/chrome-stable-raw.json` for reference

Deliverable: one command prints Chrome Stable's real TLS fingerprint as JSON.

#### 1.3 Understand the reflector output

Before writing normalize/diff, study what tlsfingerprint.io actually returns.

- [ ] Read the saved JSON from 1.2 carefully
- [ ] Identify which fields are structural (stable across runs)
- [ ] Identify which fields are noise (change every run)
- [ ] Run capture twice, diff the raw JSON manually to confirm noise fields
- [ ] Document the JSON schema in a comment or `fixtures/schema-notes.md`

Deliverable: you know exactly which fields to keep and which to strip.

#### 1.4 Normalize

- [ ] Create `src/normalize.ts`
- [ ] Input: raw ClientHello JSON (from capture or file)
- [ ] Strip noise (based on 1.3 findings):
      - GREASE values → `"GREASE"`
      - `random` bytes
      - `session_id`
      - `key_share` public key bytes (keep group IDs only)
      - Any other per-run noise found in 1.3
- [ ] Keep structural fields:
      - Cipher suite list (order preserved)
      - Extension list (type + order)
      - Supported versions
      - Key share groups
      - ALPN values
      - Signature algorithms
- [ ] Output: normalized JSON
- [ ] Test: capture twice → normalize both → outputs must be identical

Deliverable: `normalize()` turns noisy raw JSON into stable fingerprint.

#### 1.5 Diff

- [ ] Create `src/diff.ts`
- [ ] Input: two normalized fingerprint JSON objects
- [ ] Compare field by field:
      - Cipher suites: added / removed / reordered
      - Extensions: added / removed / reordered
      - Supported versions: changed
      - Key share groups: changed
      - ALPN: changed
      - Signature algorithms: changed
- [ ] Output: `{ hasChanges: boolean, changes: [...] }`
- [ ] Test: same fingerprint → no changes
- [ ] Test: manually edit a baseline (remove a cipher) → reports the change

Deliverable: `diff()` detects and reports structural fingerprint changes.

#### 1.6 End-to-end for Chrome Stable

Wire capture → normalize → diff into one command for a single browser.

- [ ] Create `src/run.ts`
- [ ] Flow:
      1. Load baseline from `fixtures/baselines/chrome-stable.json`
         (if no baseline exists, capture + normalize + save as baseline, done)
      2. Capture → normalize → diff against baseline
      3. If changed: print report, save new baseline
      4. If unchanged: print "no changes"
- [ ] CLI: `npx tsx src/run.ts`
- [ ] Test: first run creates baseline. Second run reports no changes.
- [ ] Test: upgrade Chrome → run again → reports changes (or wait for
      a real update and verify)

Deliverable: single command detects Chrome Stable fingerprint drift.

#### 1.7 Multi-browser support

Generalize capture to support all target browsers.

- [ ] Install remaining browsers:
      ```bash
      apt install google-chrome-beta
      apt install microsoft-edge-stable
      apt install firefox
      # Firefox Nightly
      curl -L "https://download.mozilla.org/?product=firefox-nightly-latest&os=linux64" \
        | tar -xjf - -C /opt/firefox-nightly
      ```
- [ ] Refactor `src/capture.ts` to accept browser config:
      ```typescript
      type BrowserConfig = {
        name: string           // 'chrome-stable', 'firefox-nightly', etc.
        type: 'chrome' | 'firefox' | 'edge'
        binaryPath: string
      }
      ```
- [ ] Chrome/Edge: `chrome.Options` / `edge.Options` + `--headless=new`
- [ ] Firefox: `firefox.Options` + `-headless`
- [ ] Define browser configs in `src/browsers.ts`:
      ```typescript
      export const browsers: BrowserConfig[] = [
        { name: 'chrome-stable', type: 'chrome', binaryPath: '/usr/bin/google-chrome-stable' },
        { name: 'chrome-beta',   type: 'chrome', binaryPath: '/usr/bin/google-chrome-beta' },
        { name: 'edge-stable',   type: 'edge',   binaryPath: '/usr/bin/microsoft-edge-stable' },
        { name: 'firefox-stable',type: 'firefox', binaryPath: '/usr/bin/firefox' },
        { name: 'firefox-nightly',type:'firefox', binaryPath: '/opt/firefox-nightly/firefox' },
      ]
      ```
- [ ] Update `src/run.ts` to loop over all browsers
- [ ] CLI:
      ```bash
      npx tsx src/run.ts                        # all browsers
      npx tsx src/run.ts --browser chrome-stable # single browser
      ```
- [ ] Test: each browser produces valid, distinct fingerprints

Deliverable: one command captures and diffs all 5 browsers.

#### 1.8 Notification

- [ ] Create `src/report.ts`:
      - Format diff results into GitHub Issue markdown
      - Title: `[chrome-stable] TLS fingerprint changed`
      - Body: structured diff (what was added/removed/reordered)
- [ ] Add `--notify` flag to `src/run.ts`:
      - If any browser changed + `--notify` is set:
        `gh issue create --title "..." --body "..."`
- [ ] Test: manually edit a baseline, run with `--notify`, verify Issue created

Deliverable: fingerprint changes automatically open GitHub Issues.

#### 1.9 Cron

- [ ] Write `scripts/install-browsers.sh` that installs all browsers
- [ ] Add to crontab:
      ```
      0 6 * * * cd /path/to/parroteer && npx tsx src/run.ts --notify 2>&1 >> /var/log/parroteer.log
      ```
- [ ] Verify: wait one day, check log and GitHub Issues

Deliverable: fully automated daily fingerprint monitoring.

### Phase 2: Parrot Generation + QUIC

- [ ] Implement ClientHello → ClientHelloSpec Go code generator
- [ ] Implement replay check (gen spec → connect to reflector → compare)
- [ ] Deploy self-hosted reflector (needed for QUIC Alt-Svc)
- [ ] Add QUIC Initial capture (two visits for Alt-Svc upgrade)
- [ ] Implement QUIC normalization + QUICSpec generator
- [ ] On successful replay: open draft PR with generated Go code

### Future: Safari / iOS

- [ ] Safari via GitHub Actions macOS runner + safaridriver
- [ ] iOS via Xcode simulator or real device
- [ ] Or manual capture when Apple releases major updates (~2x/year)

## Known Challenges

**Headless mode matters:** Chrome's legacy headless shell and new headless
mode produce different TLS fingerprints. Always use `--headless=new` for
Chrome/Edge. Firefox uses `-headless` which runs the real browser engine.

**QUIC requires two visits:** Browsers use TCP on first connection. The
reflector must send `Alt-Svc` header so the browser upgrades to QUIC on the
second visit. Only relevant in Phase 2.

**Safari requires macOS:** Safari's TLS fingerprint comes from Apple's
SecureTransport, which only exists on macOS/iOS. Cannot be captured on Linux.

## Status

Early design phase.

## License

TBD
