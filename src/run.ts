import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { capture, BROWSERS, type BrowserConfig } from "./capture.js";
import { normalize, type NormalizedFingerprint } from "./normalize.js";
import { diffFingerprints, formatReport, formatUtlsComparison, type DiffResult } from "./report.js";

const BASELINES_DIR = path.resolve("fixtures/baselines");
const KNOWN_DIFFS_DIR = path.resolve("fixtures/known-diffs");
const CAPTURES_DIR = path.resolve("fixtures/captures");
const SPECS_DIR = path.resolve("fixtures/specs");
const REPORTS_DIR = path.resolve("reports");

// Map browser type to utls parrot name
const UTLS_PARROT_MAP: Record<string, string> = {
  chrome: "chrome",
  edge: "edge",
  firefox: "firefox",
  safari: "safari",
};

interface Baseline {
  fingerprint: NormalizedFingerprint;
  captured_at: string;
}

interface KnownDiff {
  diff_hash: string;
  recorded_at: string;
}

function loadBaseline(browserName: string): Baseline | null {
  const file = path.join(BASELINES_DIR, `${browserName}.json`);
  if (!fs.existsSync(file)) return null;
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  if (data.ja3n_text && !data.fingerprint) return null;
  return data;
}

function saveBaseline(browserName: string, fp: NormalizedFingerprint): void {
  fs.mkdirSync(BASELINES_DIR, { recursive: true });
  const baseline: Baseline = { fingerprint: fp, captured_at: new Date().toISOString() };
  fs.writeFileSync(path.join(BASELINES_DIR, `${browserName}.json`), JSON.stringify(baseline, null, 2) + "\n");
}

function hashDiff(diff: DiffResult): string {
  if (!diff.hasChanges) return "match";
  const key = diff.diffs
    .map((d) => `${d.field}:${d.baseline}→${d.current}`)
    .sort()
    .join("|");
  return key;
}

function loadKnownDiff(label: string): KnownDiff | null {
  const file = path.join(KNOWN_DIFFS_DIR, `${label}.json`);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function saveKnownDiff(label: string, diffHash: string): void {
  fs.mkdirSync(KNOWN_DIFFS_DIR, { recursive: true });
  const known: KnownDiff = { diff_hash: diffHash, recorded_at: new Date().toISOString() };
  fs.writeFileSync(path.join(KNOWN_DIFFS_DIR, `${label}.json`), JSON.stringify(known, null, 2) + "\n");
}

function saveRawCapture(name: string, data: Record<string, unknown>): string {
  fs.mkdirSync(CAPTURES_DIR, { recursive: true });
  const file = path.join(CAPTURES_DIR, `${name}-${new Date().toISOString().slice(0, 10)}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
  return file;
}

function captureUtls(parrotName: string): Record<string, unknown> | null {
  try {
    const out = execSync(`go run cmd/utls-capture/main.go ${parrotName}`, {
      timeout: 30000,
      encoding: "utf8",
    });
    const result = JSON.parse(out);
    saveRawCapture(`utls-${parrotName}`, result);
    return result;
  } catch (err) {
    console.error(`  utls ${parrotName} capture failed: ${(err as Error).message}`);
    return null;
  }
}

// Generate a utls spec JSON from a raw capture file, then replay-verify it.
// Returns { specPath, verified } or null on failure.
function generateAndVerifySpec(
  browserName: string,
  captureFile: string,
): { specPath: string; specJSON: string; verified: boolean } | null {
  fs.mkdirSync(SPECS_DIR, { recursive: true });
  const specFile = path.join(SPECS_DIR, `${browserName}-spec.json`);

  // Phase 2.1: generate spec
  try {
    execSync(`go run cmd/gen-spec/main.go ${captureFile} ${specFile}`, {
      timeout: 30000,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    console.error(`    gen-spec failed: ${(err as Error).message}`);
    return null;
  }

  const specJSON = fs.readFileSync(specFile, "utf8");

  // Phase 2.2: replay-verify
  try {
    const out = execSync(`go run cmd/replay-verify/main.go ${specFile} ${captureFile}`, {
      timeout: 30000,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    const verified = out.includes("MATCH");
    return { specPath: specFile, specJSON, verified };
  } catch (err) {
    // Exit code 1 = mismatch, exit code 2 = error
    const output = (err as { stdout?: string }).stdout ?? "";
    if (output.includes("MISMATCH")) {
      console.error(`    replay-verify: MISMATCH`);
      return { specPath: specFile, specJSON, verified: false };
    }
    console.error(`    replay-verify failed: ${(err as Error).message}`);
    return { specPath: specFile, specJSON, verified: false };
  }
}

function browserExists(config: BrowserConfig): boolean {
  return fs.existsSync(config.binaryPath);
}

async function main() {
  const args = process.argv.slice(2);
  const browserFilter = args.indexOf("--browser") !== -1 ? args[args.indexOf("--browser") + 1] : null;
  const notify = args.includes("--notify");

  const browsers = browserFilter
    ? BROWSERS.filter((b) => b.name === browserFilter)
    : BROWSERS.filter(browserExists);

  if (browsers.length === 0) {
    console.error("No browsers found. Install at least one browser.");
    process.exit(1);
  }

  console.log(`Capturing ${browsers.length} browser(s): ${browsers.map((b) => b.name).join(", ")}\n`);

  // Capture all needed utls parrots
  const utlsParrotTypes = new Set(browsers.map((b) => UTLS_PARROT_MAP[b.type]).filter(Boolean));
  const utlsFingerprints: Record<string, NormalizedFingerprint> = {};

  for (const parrotName of utlsParrotTypes) {
    console.log(`Capturing utls Hello${parrotName[0].toUpperCase() + parrotName.slice(1)}_Auto parrot...`);
    const result = captureUtls(parrotName);
    if (result) {
      const fp = normalize(result);
      utlsFingerprints[parrotName] = fp;
      console.log(`  cipher_suites: [${fp.cipher_suites.join(", ")}]`);
      console.log(`  extensions:    [${fp.extensions.join(", ")}]\n`);
    }
  }

  const reports: string[] = [];
  let anyNewChange = false;

  for (const browser of browsers) {
    console.log(`Capturing ${browser.name}...`);

    let result: Record<string, unknown>;
    try {
      result = await capture(browser);
    } catch (err) {
      console.error(`  FAILED: ${(err as Error).message}\n`);
      continue;
    }

    const captureFile = saveRawCapture(browser.name, result);
    const hasTls = !!result.tls;
    console.log(`  response keys: [${Object.keys(result).join(", ")}]`);
    console.log(`  has tls object: ${hasTls}`);

    const fp = normalize(result);
    console.log(`  cipher_suites: [${fp.cipher_suites.join(", ")}]`);
    console.log(`  extensions:    [${fp.extensions.join(", ")}]`);
    console.log(`  supported_versions: [${fp.supported_versions.join(", ")}]`);
    console.log(`  signature_algorithms: [${fp.signature_algorithms.join(", ")}]`);

    // Compare against baseline (browser fingerprint drift detection)
    const baseline = loadBaseline(browser.name);
    if (!baseline) {
      console.log(`  No baseline found. Saving initial baseline.`);
      saveBaseline(browser.name, fp);
    } else {
      const diff = diffFingerprints(baseline.fingerprint, fp);
      if (diff.hasChanges) {
        console.log(`  CHANGED since baseline!`);
        reports.push(formatReport(browser.name, baseline.fingerprint, fp, diff));
        saveBaseline(browser.name, fp);
        anyNewChange = true;
      } else {
        console.log(`  No change from baseline.`);
      }
    }

    // Compare real browser vs its utls parrot
    const parrotName = UTLS_PARROT_MAP[browser.type];
    const utlsFp = parrotName ? utlsFingerprints[parrotName] : null;
    if (utlsFp) {
      const utlsDiff = diffFingerprints(utlsFp, fp);
      const label = `${browser.name} vs utls ${parrotName}`;
      const diffHash = hashDiff(utlsDiff);
      const knownDiff = loadKnownDiff(`${browser.name}-vs-utls-${parrotName}`);

      if (utlsDiff.hasChanges) {
        console.log(`  utls ${parrotName} parrot DIFFERS from real ${browser.name}!`);
        reports.push(formatUtlsComparison(label, fp, utlsFp, utlsDiff));

        if (knownDiff?.diff_hash === diffHash) {
          console.log(`  (known diff, skipping notification)`);
        } else {
          console.log(`  (NEW diff detected, will notify)`);
          anyNewChange = true;
          saveKnownDiff(`${browser.name}-vs-utls-${parrotName}`, diffHash);
        }

        // Generate and verify a corrected spec from the real browser capture
        console.log(`  Generating spec from real ${browser.name} capture...`);
        const specResult = generateAndVerifySpec(browser.name, captureFile);
        if (specResult) {
          const status = specResult.verified ? "MATCH" : "MISMATCH";
          console.log(`  Replay verification: ${status}`);
          const statusEmoji = specResult.verified ? "Replay verified" : "Replay MISMATCH — review manually";
          reports.push(
            `### ${browser.name} — Generated Spec (${statusEmoji})\n\n` +
            "```json\n" + specResult.specJSON + "\n```\n",
          );
        }
      } else {
        console.log(`  utls ${parrotName} parrot matches.`);
        reports.push(formatUtlsComparison(label, fp, utlsFp, utlsDiff));
        if (knownDiff) {
          saveKnownDiff(`${browser.name}-vs-utls-${parrotName}`, "match");
        }
      }
    }

    console.log();
  }

  // Output reports
  if (reports.length > 0) {
    const fullReport = `# Parroteer Fingerprint Report\n\n${new Date().toISOString()}\n\n${reports.join("\n---\n\n")}`;

    // Save report
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
    const reportFile = path.join(REPORTS_DIR, `report-${new Date().toISOString().slice(0, 10)}.md`);
    fs.writeFileSync(reportFile, fullReport);
    console.log(`\nReport saved to ${reportFile}`);

    // Print report
    console.log("\n" + "=".repeat(60));
    console.log(fullReport);
    console.log("=".repeat(60));

    // Notify via GitHub Issue — only if there's a genuinely new change
    if (notify && anyNewChange) {
      const title = `[Parroteer] TLS fingerprint changes detected — ${new Date().toISOString().slice(0, 10)}`;
      try {
        execSync(`gh issue create --title "${title}" --body "$(cat ${reportFile})"`, {
          encoding: "utf8",
          stdio: "inherit",
        });
        console.log("\nGitHub Issue created.");
      } catch {
        console.error("\nFailed to create GitHub Issue. Is gh CLI configured?");
      }
    }
  } else {
    console.log("No changes detected. All fingerprints match baselines.");
  }
}

main();
