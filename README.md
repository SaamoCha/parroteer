# Parroteer

Automated browser fingerprint monitoring and parrot generation pipeline for
[utls](https://github.com/refraction-networking/utls) and
[uquic](https://github.com/refraction-networking/uquic).

Watches real browser releases, captures their TLS/QUIC fingerprints against a
reflector, diffs against existing parrot presets, and generates candidate
updates as draft PRs.

## Why

utls/uquic maintain hand-crafted "parrot" presets that mimic real browser
fingerprints. When Chrome or Firefox ships a new version that changes cipher
suites, extensions, or QUIC transport parameters, the parrots go stale.
Today this is noticed manually, sometimes weeks late. Parroteer closes that
gap.

## How It Works

```
cron (GitHub Actions)
  │
  ├─ 1. Watch ── poll Chrome for Testing JSON / Firefox release channels
  │               → did any channel version change?
  │
  ├─ 2. Capture ── launch real browser (Playwright, branded channels)
  │                 → hit reflector (clienthellod)
  │                 → get structured TLS ClientHello + QUIC Initial JSON
  │
  ├─ 3. Normalize ── strip GREASE values, random, session ID
  │                   → produce stable structural fingerprint
  │
  ├─ 4. Diff ── compare against baseline (last known fingerprint)
  │             → classify: info / warning / change
  │
  ├─ 5. Generate ── if structure changed:
  │                  → produce utls ClientHelloSpec (Go code)
  │                  → produce uquic QUICSpec candidate (Initial Packet only)
  │
  └─ 6. Notify ── info: log only
                   warning: open GitHub Issue
                   change + replay passes: open draft PR
```

## Architecture

```
parroteer/
├── .github/
│   └── workflows/
│       └── fingerprint-watch.yml    # cron + manual dispatch
│
├── cmd/
│   ├── watcher/                     # poll browser release channels
│   │   └── main.go
│   ├── capture/                     # launch browser, hit reflector
│   │   └── main.go
│   └── gen-parrot/                  # generate ClientHelloSpec / QUICSpec
│       └── main.go
│
├── internal/
│   ├── channels/                    # browser release channel polling
│   │   ├── chrome.go                # Chrome for Testing JSON
│   │   └── firefox.go               # Firefox Stable/Beta/Nightly
│   ├── normalize/                   # strip noise, produce stable fingerprint
│   │   ├── tls.go
│   │   └── quic.go
│   ├── diff/                        # structural diff, severity classification
│   │   └── diff.go
│   └── generator/                   # produce Go parrot code
│       ├── utls.go                  # ClientHello → ClientHelloSpec
│       └── uquic.go                 # QUIC Initial → QUICSpec
│
├── fixtures/
│   └── baselines/                   # last known normalized fingerprints
│       ├── chrome-stable.json
│       ├── chrome-beta.json
│       ├── firefox-stable.json
│       └── firefox-nightly.json
│
├── parrots/
│   └── generated/                   # auto-generated parrot Go files
│
├── reports/                         # diff reports, CI artifacts
│
├── go.mod
└── go.sum
```

## Browser Channels

| Browser | Source | Polling Method |
|---|---|---|
| Chrome Stable | Chrome for Testing JSON | HTTP GET, parse version |
| Chrome Beta | Chrome for Testing JSON | HTTP GET, parse version |
| Chrome Dev | Chrome for Testing JSON | HTTP GET, parse version |
| Chrome Canary | Chrome for Testing JSON | HTTP GET, parse version |
| Edge Stable | Playwright branded channel | Playwright launch |
| Firefox Stable | Mozilla release API | HTTP GET, parse version |
| Firefox Beta | Mozilla archive | HTTP GET, parse version |
| Firefox Nightly | Mozilla archive | HTTP GET, parse version |

## Reflector

Uses [clienthellod](https://github.com/gaukas/clienthellod) as the TLS/QUIC
reflection service. The reflector:

- Captures TLS ClientHello and returns structured JSON
- Captures QUIC Client Initial and returns structured JSON
- Provides fingerprint IDs for quick comparison

The reflector must be deployed externally (not on the CI runner) with a valid
TLS certificate. QUIC capture requires the reflector to advertise `Alt-Svc`
so the browser upgrades to QUIC on subsequent visits.

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

### QUIC — keep:
- DCID / SCID length
- Token length
- Packet number length
- Frame types and order
- Transport parameters set and order
- UDP datagram size

### QUIC — discard:
- Connection ID values
- Token values
- GREASE specific values

## Severity Levels

| Level | Condition | Action |
|---|---|---|
| Info | Version changed, fingerprint unchanged | Log only |
| Warning | Fingerprint structure changed | Open GitHub Issue |
| Change | Structure changed + generator produces valid parrot | Open draft PR |

## Generation Criteria

A generated parrot is only promoted to draft PR if:

1. TLS structural diff is fully explainable
2. Generated `ClientHelloSpec` compiles
3. Replay with new spec against reflector matches real browser fingerprint
4. QUIC: only Initial Packet fields align (conservative)
5. Any ECH / token / PSK / retry anomaly → downgrade to warning, no code change

## Development Plan

### Phase 1: Chrome TLS (MVP)

- [ ] Set up reflector (deploy clienthellod with valid cert)
- [ ] Write version watcher for Chrome for Testing JSON
- [ ] Write Playwright capture script (Chrome Stable, `channel: 'chrome'`)
- [ ] Store raw + normalized fingerprint as baseline
- [ ] GitHub Actions workflow: cron daily, capture, diff against baseline
- [ ] On diff: open GitHub Issue with structured report

### Phase 2: Diff Automation

- [ ] Implement TLS normalization (strip GREASE, random, session ID)
- [ ] Implement structural diff with severity classification
- [ ] Add Chrome Beta/Dev/Canary channels
- [ ] Add Edge Stable via Playwright branded channel

### Phase 3: Parrot Generation

- [ ] Implement ClientHello → ClientHelloSpec generator
- [ ] Implement replay check (gen spec → connect to reflector → compare)
- [ ] On successful replay: open draft PR with generated Go code
- [ ] Add generation criteria checks (compile, replay match, no anomalies)

### Phase 4: Firefox + QUIC

- [ ] Add Firefox Stable/Beta/Nightly (download binary, executablePath)
- [ ] Add QUIC Initial capture (reflector must advertise Alt-Svc)
- [ ] Implement QUIC normalization
- [ ] Implement QUICSpec generator (Initial Packet only)
- [ ] QUIC anomalies → warning only, no auto-generation

## Known Challenges

**Playwright Chromium vs real Chrome:** Playwright's bundled Chromium lacks
Google's proprietary patches. Fingerprints differ. Must use `channel: 'chrome'`
to launch the real Chrome binary pre-installed on GitHub Actions runners.

**QUIC requires two visits:** Browsers use TCP on first connection. The
reflector must send `Alt-Svc` header so the browser upgrades to QUIC on the
second visit. Capture script must visit twice.

**Reflector hosting:** Needs a stable external host with valid TLS cert.
Cannot run on localhost in CI without cert setup. Simplest: deploy on a
cheap VPS with Let's Encrypt.

## Status

Early design phase.

## License

TBD
