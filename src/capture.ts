import { Builder, By } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";
import firefox from "selenium-webdriver/firefox.js";
import edge from "selenium-webdriver/edge.js";

// Use the root endpoint (not /json) — it returns full tls object with
// extension details (supported_versions, key_share, signature_algorithms).
// The /json endpoint only returns ja3/ja4 summaries without these fields.
const REFLECTOR_URL = "https://tls.browserleaks.com/";

export interface BrowserConfig {
  name: string;
  type: "chrome" | "firefox" | "edge";
  binaryPath: string;
}

// Each browser lists candidate paths in priority order.
// The first path that exists on disk wins. This handles differences
// between local dev (snap Firefox) and CI (apt Firefox).
export const BROWSERS: BrowserConfig[] = resolveBrowserPaths([
  { name: "chrome-stable", type: "chrome", candidates: ["/usr/bin/google-chrome-stable"] },
  { name: "chrome-beta", type: "chrome", candidates: ["/usr/bin/google-chrome-beta"] },
  { name: "edge-stable", type: "edge", candidates: ["/usr/bin/microsoft-edge-stable"] },
  { name: "firefox-stable", type: "firefox", candidates: [
    "/usr/bin/firefox",
    "/snap/firefox/current/usr/lib/firefox/firefox",
  ]},
  { name: "firefox-nightly", type: "firefox", candidates: ["/opt/firefox-nightly/firefox"] },
]);

function resolveBrowserPaths(
  configs: { name: string; type: BrowserConfig["type"]; candidates: string[] }[],
): BrowserConfig[] {
  const fs = require("fs") as typeof import("fs");
  return configs.map(({ name, type, candidates }) => ({
    name,
    type,
    binaryPath: candidates.find((p) => fs.existsSync(p)) ?? candidates[0],
  }));
}

export async function capture(browser: BrowserConfig): Promise<Record<string, unknown>> {
  let driver;

  if (browser.type === "chrome") {
    const options = new chrome.Options();
    options.addArguments("--headless=new");
    options.setChromeBinaryPath(browser.binaryPath);
    driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  } else if (browser.type === "edge") {
    // Edge uses the same Options API as Chrome under the hood
    const options = new edge.Options();
    options.addArguments("--headless=new");
    options.setEdgeChromiumBinaryPath(browser.binaryPath);
    driver = await new Builder().forBrowser("MicrosoftEdge").setEdgeOptions(options).build();
  } else {
    const options = new firefox.Options();
    options.addArguments("-headless");
    options.setBinary(browser.binaryPath);
    // Disable Firefox's built-in JSON viewer so we get raw JSON text
    options.setPreference("devtools.jsonview.enabled", false);
    driver = await new Builder().forBrowser("firefox").setFirefoxOptions(options).build();
  }

  try {
    await driver.get(REFLECTOR_URL);

    await driver.get(REFLECTOR_URL);
    const body = await driver.findElement(By.tagName("body"));
    const text = await body.getText();
    return JSON.parse(text);
  } finally {
    await driver.quit();
  }
}

// CLI: npx tsx src/capture.ts [--browser chrome-stable]
if (process.argv[1]?.endsWith("capture.ts")) {
  const args = process.argv.slice(2);
  const browserIdx = args.indexOf("--browser");
  const browserName = browserIdx !== -1 ? args[browserIdx + 1] : "chrome-stable";

  const config = BROWSERS.find((b) => b.name === browserName);
  if (!config) {
    console.error(`Unknown browser: ${browserName}. Available: ${BROWSERS.map((b) => b.name).join(", ")}`);
    process.exit(1);
  }

  capture(config).then((result) => {
    console.log(JSON.stringify(result, null, 2));
  }).catch((err) => {
    console.error(`Capture failed for ${browserName}: ${err.message}`);
    process.exit(1);
  });
}
