import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { capture, BROWSERS, type BrowserConfig } from "./capture.js";
import { normalize, type NormalizedFingerprint } from "./normalize.js";
import { diffFingerprints, formatReport, formatUtlsComparison } from "./report.js";

const BASELINES_DIR = path.resolve("fixtures/baselines");
const REPORTS_DIR = path.resolve("reports");

// Map browser type to utls parrot name
const UTLS_PARROT_MAP: Record<string, string> = {
  chrome: "chrome",
  edge: "edge",
  firefox: "firefox",
};

interface Baseline {
  fingerprint: NormalizedFingerprint;
  captured_at: string;
}

function loadBaseline(browserName: string): Baseline | null {
  const file = path.join(BASELINES_DIR, `${browserName}.json`);
  if (!fs.existsSync(file)) return null;
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  // Support legacy baselines that only have ja3n_text
  if (data.ja3n_text && !data.fingerprint) return null;
  return data;
}

function saveBaseline(browserName: string, fp: NormalizedFingerprint): void {
  fs.mkdirSync(BASELINES_DIR, { recursive: true });
  const baseline: Baseline = { fingerprint: fp, captured_at: new Date().toISOString() };
  fs.writeFileSync(path.join(BASELINES_DIR, `${browserName}.json`), JSON.stringify(baseline, null, 2) + "\n");
}

function captureUtls(parrotName: string): Record<string, unknown> | null {
  try {
    const out = execSync(`go run cmd/utls-capture/main.go ${parrotName}`, {
      timeout: 30000,
      encoding: "utf8",
    });
    return JSON.parse(out);
  } catch (err) {
    console.error(`  utls ${parrotName} capture failed: ${(err as Error).message}`);
    return null;
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
  let anyChange = false;

  for (const browser of browsers) {
    console.log(`Capturing ${browser.name}...`);

    let result: Record<string, unknown>;
    try {
      result = await capture(browser);
    } catch (err) {
      console.error(`  FAILED: ${(err as Error).message}\n`);
      continue;
    }

    const fp = normalize(result);
    console.log(`  cipher_suites: [${fp.cipher_suites.join(", ")}]`);
    console.log(`  extensions:    [${fp.extensions.join(", ")}]`);

    // Compare against baseline
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
        anyChange = true;
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
      if (utlsDiff.hasChanges) {
        console.log(`  utls ${parrotName} parrot DIFFERS from real ${browser.name}!`);
        reports.push(formatUtlsComparison(label, fp, utlsFp, utlsDiff));
        anyChange = true;
      } else {
        console.log(`  utls ${parrotName} parrot matches.`);
        reports.push(formatUtlsComparison(label, fp, utlsFp, utlsDiff));
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

    // Notify via GitHub Issue
    if (notify && anyChange) {
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
