/**
 * run-quic.ts — QUIC counterpart of run.ts.
 *
 * Captures QUIC Initial fingerprints from real browsers (via the local
 * reflector) and from uquic parrots (offline, cmd/uquic-capture), then:
 *   - compares each browser with its previous baseline (QUIC drift)
 *   - compares each browser with its uquic parrot (parrot accuracy)
 *   - records known diffs so the same mismatch is reported only once
 *
 * Usage: npx tsx src/run-quic.ts [--browser chrome-stable] [--notify]
 */
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { BROWSERS, type BrowserConfig } from "./capture.js";
import { captureQuic } from "./capture-quic.js";
import { normalizeQuic, type NormalizedQuicFingerprint } from "./normalize-quic.js";
import { diffQuic, formatQuicReport, formatUquicComparison, type QuicDiffResult } from "./report-quic.js";

const BASELINES_DIR = path.resolve("fixtures/baselines");
const KNOWN_DIFFS_DIR = path.resolve("fixtures/known-diffs");
const CAPTURES_DIR = path.resolve("fixtures/captures");
const REPORTS_DIR = path.resolve("reports");

const QUIC_BROWSERS = ["chrome-stable", "edge-stable", "firefox-stable"];

// uquic has no Edge parrot; Edge is Chromium, so it is compared with Chrome.
const UQUIC_PARROT_MAP: Record<string, string> = { chrome: "chrome", edge: "chrome", firefox: "firefox" };

const UQUIC_PARROT_NAMES: Record<string, string> = { chrome: "QUICChrome_146", firefox: "QUICFirefox_116" };

interface Baseline {
  fingerprint: NormalizedQuicFingerprint;
  captured_at: string;
}

function readJSON<T>(file: string): T | null {
  return fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as T) : null;
}

function writeJSON(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

function hashDiff(diff: QuicDiffResult): string {
  if (!diff.hasChanges) return "match";
  return diff.diffs.map((d) => `${d.field}:${d.baseline}→${d.current}`).sort().join("|");
}

function saveRawCapture(name: string, data: Record<string, unknown>): string {
  const file = path.join(CAPTURES_DIR, `${name}-${new Date().toISOString().slice(0, 10)}.json`);
  writeJSON(file, data);
  return file;
}

// Patch the uquic parrot toward the real capture (cmd/gen-quic-spec), record the
// patched spec's Initial flight, and compare it with the real browser again.
function patchAndReplay(browserName: string, parrot: string, captureFile: string, real: NormalizedQuicFingerprint): string | null {
  const out = path.join(CAPTURES_DIR, `${browserName}-quic-patched-uquic-${parrot}.json`);
  let patchNotes: string;
  try {
    patchNotes = execSync(`go run ./cmd/gen-quic-spec -capture ${captureFile} -parrot ${parrot} -out ${out}`, {
      timeout: 120000,
      encoding: "utf8",
    }).trim();
  } catch (err) {
    console.error(`    gen-quic-spec failed: ${(err as Error).message}`);
    return null;
  }
  const remaining = diffQuic(normalizeQuic(JSON.parse(fs.readFileSync(out, "utf8"))), real);
  console.log(`  Patched uquic ${parrot} spec: ${remaining.hasChanges ? "Replay MISMATCH" : "Replay MATCH"}`);
  let section = `### ${browserName} — patched uquic ${UQUIC_PARROT_NAMES[parrot]} (${remaining.hasChanges ? "Replay MISMATCH, still differs below" : "Replay MATCH"})\n\n`;
  section += `Patch applied by gen-quic-spec:\n${patchNotes}\n\n`;
  if (remaining.hasChanges) {
    section += "Still different after the patch (needs a manual change, e.g. a missing TLS extension):\n";
    for (const d of remaining.diffs) {
      const parts = [];
      if (d.added.length) parts.push(`real only: ${d.added.join(", ")}`);
      if (d.removed.length) parts.push(`patched only: ${d.removed.join(", ")}`);
      if (!parts.length) parts.push(`real=\`${d.current}\` patched=\`${d.baseline}\``);
      section += `- ${d.field}: ${parts.join("; ")}\n`;
    }
  }
  return section;
}

function captureUquic(parrot: string): NormalizedQuicFingerprint | null {
  try {
    const out = execSync(`go run ./cmd/uquic-capture -parrot ${parrot}`, { timeout: 120000, encoding: "utf8" });
    const raw = JSON.parse(out);
    saveRawCapture(`uquic-${parrot}`, raw);
    return normalizeQuic(raw);
  } catch (err) {
    console.error(`  uquic ${parrot} capture failed: ${(err as Error).message}`);
    return null;
  }
}

function logFingerprint(fp: NormalizedQuicFingerprint): void {
  console.log(`  packets: ${fp.packet_count}, frames: [${fp.frame_types.join(", ")}]`);
  console.log(`  transport_parameter_ids: [${fp.transport_parameter_ids.join(", ")}]`);
  console.log(`  supported_groups: [${fp.supported_groups.join(", ")}]`);
}

async function main() {
  const args = process.argv.slice(2);
  const filter = args.indexOf("--browser") !== -1 ? args[args.indexOf("--browser") + 1] : null;
  const notify = args.includes("--notify");

  const browsers: BrowserConfig[] = BROWSERS.filter((b) => QUIC_BROWSERS.includes(b.name))
    .filter((b) => (filter ? b.name === filter : true))
    .filter((b) => fs.existsSync(b.binaryPath) || !!process.env[`${b.name.toUpperCase().replace(/-/g, "_")}_BINARY`]);
  if (browsers.length === 0) {
    console.error("No QUIC-capable browsers found.");
    process.exit(1);
  }
  console.log(`QUIC capture for ${browsers.length} browser(s): ${browsers.map((b) => b.name).join(", ")}\n`);

  const parrots: Record<string, NormalizedQuicFingerprint> = {};
  for (const parrot of new Set(browsers.map((b) => UQUIC_PARROT_MAP[b.type]))) {
    console.log(`Capturing uquic ${UQUIC_PARROT_NAMES[parrot]} parrot...`);
    const fp = captureUquic(parrot);
    if (fp) {
      parrots[parrot] = fp;
      logFingerprint(fp);
    }
    console.log();
  }

  const reports: string[] = [];
  let anyNewChange = false;

  for (const browser of browsers) {
    console.log(`Capturing ${browser.name} over QUIC...`);
    let raw: Record<string, unknown> | null;
    try {
      raw = await captureQuic(browser);
    } catch (err) {
      console.error(`  FAILED: ${(err as Error).message}\n`);
      continue;
    }
    if (!raw) {
      console.error(`  FAILED: no QUIC fingerprint\n`);
      continue;
    }
    const captureFile = saveRawCapture(`${browser.name}-quic`, raw);
    const fp = normalizeQuic(raw);
    logFingerprint(fp);

    const baselineFile = path.join(BASELINES_DIR, `${browser.name}-quic.json`);
    const baseline = readJSON<Baseline>(baselineFile);
    if (!baseline) {
      console.log(`  No QUIC baseline found. Saving initial baseline.`);
      writeJSON(baselineFile, { fingerprint: fp, captured_at: new Date().toISOString() });
    } else {
      const diff = diffQuic(baseline.fingerprint, fp);
      if (diff.hasChanges) {
        console.log(`  CHANGED since baseline!`);
        reports.push(formatQuicReport(browser.name, diff));
        writeJSON(baselineFile, { fingerprint: fp, captured_at: new Date().toISOString() });
        anyNewChange = true;
      } else {
        console.log(`  No change from baseline.`);
      }
    }

    const parrot = UQUIC_PARROT_MAP[browser.type];
    const parrotFp = parrots[parrot];
    if (parrotFp) {
      const diff = diffQuic(parrotFp, fp);
      const label = `${browser.name} vs uquic ${UQUIC_PARROT_NAMES[parrot]}`;
      const knownFile = path.join(KNOWN_DIFFS_DIR, `${browser.name}-quic-vs-uquic-${parrot}.json`);
      const known = readJSON<{ diff_hash: string }>(knownFile);
      const hash = hashDiff(diff);
      reports.push(formatUquicComparison(label, fp, diff));
      if (diff.hasChanges) {
        console.log(`  uquic ${parrot} parrot DIFFERS from real ${browser.name}!`);
        if (known?.diff_hash === hash) {
          console.log(`  (known diff, skipping notification)`);
        } else {
          console.log(`  (NEW diff detected, will notify)`);
          anyNewChange = true;
          writeJSON(knownFile, { diff_hash: hash, recorded_at: new Date().toISOString() });
        }
        const patched = patchAndReplay(browser.name, parrot, captureFile, fp);
        if (patched) reports.push(patched);
      } else {
        console.log(`  uquic ${parrot} parrot matches.`);
        if (known) writeJSON(knownFile, { diff_hash: "match", recorded_at: new Date().toISOString() });
      }
    }
    console.log();
  }

  if (reports.length === 0) {
    console.log("No QUIC fingerprints captured.");
    return;
  }
  const date = new Date().toISOString().slice(0, 10);
  const full = `# Parroteer QUIC Fingerprint Report\n\n${new Date().toISOString()}\n\n${reports.join("\n---\n\n")}`;
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const reportFile = path.join(REPORTS_DIR, `quic-report-${date}.md`);
  fs.writeFileSync(reportFile, full);
  console.log(`\nReport saved to ${reportFile}\n${"=".repeat(60)}\n${full}\n${"=".repeat(60)}`);

  if (notify && anyNewChange) {
    try {
      execSync(`gh issue create --title "[Parroteer] QUIC fingerprint changes detected — ${date}" --body-file ${reportFile}`, {
        encoding: "utf8",
        stdio: "inherit",
      });
      console.log("\nGitHub Issue created.");
    } catch {
      console.error("\nFailed to create GitHub Issue. Is gh CLI configured?");
    }
  }
}

main();
