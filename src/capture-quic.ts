/**
 * capture-quic.ts — Capture QUIC Initial fingerprints from real browsers.
 *
 * The browsers talk to a local clienthellod reflector (see
 * scripts/start-quic-reflector.sh) under a private hostname, so no public
 * domain is involved:
 *
 *   QUIC_REFLECTOR_URL   reflector URL (default https://reflector.test/)
 *   QUIC_REFLECTOR_IP    resolve the reflector host to this IP (default 127.0.0.1)
 *   QUIC_REFLECTOR_SPKI  base64 SHA-256 of the reflector certificate's SPKI,
 *                        so Chromium accepts the private certificate
 *
 * Chromium is forced onto QUIC with --origin-to-force-quic-on. Firefox uses
 * network.http.http3.alt-svc-mapping-for-testing and trusts the reflector's
 * CA through the enterprise policy the reflector script installs. Firefox is
 * also switched to its NSPR socket path: on loopback, its default GSO path
 * hands both Initial packets to the reflector in one buffer, which
 * clienthellod cannot split. The packets themselves are unchanged.
 */

import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";
import firefox from "selenium-webdriver/firefox.js";
import edge from "selenium-webdriver/edge.js";
import * as fs from "fs";
import * as path from "path";
import { BROWSERS, type BrowserConfig } from "./capture.js";

const QUIC_REFLECTOR_URL = process.env.QUIC_REFLECTOR_URL ?? "https://reflector.test/";
const QUIC_REFLECTOR_IP = process.env.QUIC_REFLECTOR_IP ?? "127.0.0.1";
const QUIC_REFLECTOR_SPKI = process.env.QUIC_REFLECTOR_SPKI ?? "";

const MAX_VISITS = 5;
const LOG_DIR = path.resolve("fixtures/captures");
const VISIT_DELAY_MS = 2000;

const host = new URL(QUIC_REFLECTOR_URL).hostname;
const port = new URL(QUIC_REFLECTOR_URL).port || "443";

// Lets local runs point at a different binary, e.g. FIREFOX_STABLE_BINARY.
function binaryFor(browser: BrowserConfig): string {
  return process.env[`${browser.name.toUpperCase().replace(/-/g, "_")}_BINARY`] ?? browser.binaryPath;
}

function chromiumArgs(): string[] {
  const args = [
    "--headless=new",
    `--host-resolver-rules=MAP ${host} ${QUIC_REFLECTOR_IP}`,
    `--origin-to-force-quic-on=${host}:${port}`,
  ];
  if (QUIC_REFLECTOR_SPKI) args.push(`--ignore-certificate-errors-spki-list=${QUIC_REFLECTOR_SPKI}`);
  return args;
}

function buildDriver(browser: BrowserConfig) {
  if (browser.type === "chrome") {
    const options = new chrome.Options();
    options.addArguments(...chromiumArgs());
    options.setChromeBinaryPath(binaryFor(browser));
    fs.mkdirSync(LOG_DIR, { recursive: true });
    const service = new chrome.ServiceBuilder().loggingTo(path.join(LOG_DIR, `${browser.name}-driver.log`)).enableVerboseLogging();
    return new Builder().forBrowser("chrome").setChromeOptions(options).setChromeService(service).build();
  }
  if (browser.type === "edge") {
    const options = new edge.Options();
    options.addArguments(...chromiumArgs());
    options.setEdgeChromiumBinaryPath(binaryFor(browser));
    fs.mkdirSync(LOG_DIR, { recursive: true });
    const service = new edge.ServiceBuilder().loggingTo(path.join(LOG_DIR, `${browser.name}-driver.log`)).enableVerboseLogging();
    return new Builder().forBrowser("MicrosoftEdge").setEdgeOptions(options).setEdgeService(service).build();
  }
  if (browser.type === "firefox") {
    const options = new firefox.Options();
    options.addArguments("-headless");
    options.setBinary(binaryFor(browser));
    options.setPreference("devtools.jsonview.enabled", false);
    options.setPreference("network.dns.forceResolve", QUIC_REFLECTOR_IP);
    options.setPreference("network.http.http3.alt-svc-mapping-for-testing", `${host};h3=:${port}`);
    options.setPreference("network.http.http3.disable_when_third_party_roots_found", false);
    options.setPreference("network.http.http3.use_nspr_for_io", true);
    return new Builder().forBrowser("firefox").setFirefoxOptions(options).build();
  }
  throw new Error(`QUIC capture is not supported for ${browser.name}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Browser start-up occasionally fails on CI runners ("session not created");
// one retry after a short pause is enough.
async function startDriver(browser: BrowserConfig) {
  try {
    return await buildDriver(browser);
  } catch (err) {
    console.log(`    ${browser.name} did not start (${(err as Error).message.split("\n")[0]}), retrying once...`);
    await sleep(5000);
    return buildDriver(browser);
  }
}

export async function captureQuic(browser: BrowserConfig): Promise<Record<string, unknown> | null> {
  const driver = await startDriver(browser);
  try {
    for (let visit = 1; visit <= MAX_VISITS; visit++) {
      await driver.get(QUIC_REFLECTOR_URL);
      const body = await driver.wait(until.elementLocated(By.tagName("body")), 15000);
      const text = (await body.getText()).trim();
      try {
        const data = JSON.parse(text);
        if (data?.ClientInitials) {
          console.log(`    Got QUIC fingerprint on visit ${visit}`);
          return data;
        }
      } catch {
        // not a QUIC fingerprint yet
      }
      console.log(`    visit ${visit}: no QUIC fingerprint yet (body: ${JSON.stringify(text.slice(0, 80))})`);
      if (visit < MAX_VISITS) await sleep(VISIT_DELAY_MS);
    }
    console.log(`    No QUIC fingerprint after ${MAX_VISITS} visits`);
    return null;
  } finally {
    await driver.quit();
  }
}

// CLI: npx tsx src/capture-quic.ts [--browser chrome-stable]
if (process.argv[1]?.endsWith("capture-quic.ts")) {
  const args = process.argv.slice(2);
  const i = args.indexOf("--browser");
  const name = i !== -1 ? args[i + 1] : "chrome-stable";
  const config = BROWSERS.find((b) => b.name === name);
  if (!config) {
    console.error(`Unknown browser: ${name}. Available: ${BROWSERS.map((b) => b.name).join(", ")}`);
    process.exit(1);
  }
  captureQuic(config)
    .then((result) => {
      if (!result) process.exit(1);
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((err) => {
      console.error(`Capture failed: ${err.message}`);
      process.exit(1);
    });
}
