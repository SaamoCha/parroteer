/**
 * capture-quic.ts — Capture QUIC Initial Packet fingerprints from real browsers.
 *
 * Flow:
 *   1. Visit quic-reflect.matseoi.com (TCP/H2) — browser gets Alt-Svc: h3
 *   2. Wait for browser to cache Alt-Svc
 *   3. Visit again — browser upgrades to QUIC (H3)
 *   4. Visit once more — clienthellod has cached the QUIC fingerprint
 *   5. Read JSON response containing QUIC Initial Packet analysis
 *
 * The QUIC reflector is a self-hosted clienthellod instance that captures
 * QUIC Initial Packets via raw UDP listener and serves the fingerprint
 * back to the client on subsequent requests.
 */

import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";
import firefox from "selenium-webdriver/firefox.js";
import edge from "selenium-webdriver/edge.js";
import safari from "selenium-webdriver/safari.js";
import { BROWSERS, type BrowserConfig } from "./capture.js";

const QUIC_REFLECTOR_URL = process.env.QUIC_REFLECTOR_URL ?? "https://quic-reflect.matseoi.com/";

// Number of visits to attempt. Browser needs at least 2 visits:
// visit 1 = TCP (gets Alt-Svc), visit 2+ = may use QUIC.
const MAX_VISITS = 5;
const VISIT_DELAY_MS = 2000;

function buildDriver(browser: BrowserConfig) {
  if (browser.type === "chrome") {
    const options = new chrome.Options();
    options.addArguments("--headless=new");
    // Enable QUIC in Chrome
    options.addArguments("--enable-quic");
    options.addArguments("--origin-to-force-quic-on=quic-reflect.matseoi.com:443");
    options.setChromeBinaryPath(browser.binaryPath);
    return new Builder().forBrowser("chrome").setChromeOptions(options).build();
  } else if (browser.type === "edge") {
    const options = new edge.Options();
    options.addArguments("--headless=new");
    options.addArguments("--enable-quic");
    options.addArguments("--origin-to-force-quic-on=quic-reflect.matseoi.com:443");
    options.setEdgeChromiumBinaryPath(browser.binaryPath);
    return new Builder().forBrowser("MicrosoftEdge").setEdgeOptions(options).build();
  } else if (browser.type === "firefox") {
    const options = new firefox.Options();
    options.addArguments("-headless");
    options.setBinary(browser.binaryPath);
    options.setPreference("devtools.jsonview.enabled", false);
    // Firefox has HTTP/3 enabled by default since ~v88
    return new Builder().forBrowser("firefox").setFirefoxOptions(options).build();
  } else {
    // Safari
    const options = new safari.Options();
    return new Builder().forBrowser("safari").setSafariOptions(options).build();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function captureQuic(browser: BrowserConfig): Promise<Record<string, unknown> | null> {
  const driver = await buildDriver(browser);

  try {
    for (let visit = 1; visit <= MAX_VISITS; visit++) {
      console.log(`    QUIC visit ${visit}/${MAX_VISITS}...`);
      await driver.get(QUIC_REFLECTOR_URL);

      // Wait for page to load
      await driver.wait(until.elementLocated(By.tagName("body")), 10000);
      const body = await driver.findElement(By.tagName("body"));
      const text = await body.getText();

      // Check if we got QUIC fingerprint data (non-empty response)
      if (text && text.trim().length > 2) {
        try {
          const data = JSON.parse(text);
          // clienthellod QUIC response has fields like quic_version, quic_cipher_suites, etc.
          // or it might wrap in a structure — check for any meaningful content
          if (data && Object.keys(data).length > 0) {
            console.log(`    Got QUIC fingerprint on visit ${visit}`);
            return data;
          }
        } catch {
          // Not JSON yet, keep trying
        }
      }

      if (visit < MAX_VISITS) {
        await sleep(VISIT_DELAY_MS);
      }
    }

    console.log(`    No QUIC fingerprint after ${MAX_VISITS} visits (browser may not have upgraded to h3)`);
    return null;
  } finally {
    await driver.quit();
  }
}

// CLI: npx tsx src/capture-quic.ts [--browser chrome-stable]
if (process.argv[1]?.endsWith("capture-quic.ts")) {
  const args = process.argv.slice(2);
  const browserIdx = args.indexOf("--browser");
  const browserName = browserIdx !== -1 ? args[browserIdx + 1] : "chrome-stable";

  const config = BROWSERS.find((b) => b.name === browserName);
  if (!config) {
    console.error(`Unknown browser: ${browserName}. Available: ${BROWSERS.map((b) => b.name).join(", ")}`);
    process.exit(1);
  }

  console.log(`Capturing QUIC fingerprint for ${browserName}...`);
  console.log(`Reflector: ${QUIC_REFLECTOR_URL}`);
  captureQuic(config).then((result) => {
    if (result) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.error("No QUIC fingerprint captured.");
      process.exit(1);
    }
  }).catch((err) => {
    console.error(`Capture failed: ${err.message}`);
    process.exit(1);
  });
}
