import { Builder, By } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";
import firefox from "selenium-webdriver/firefox.js";

const PEET_URL = "https://tls.peet.ws/api/all";

interface H2Setting {
  id: string;
  value: number;
}

interface PeetData {
  http_version: string;
  tls: { ja4: string };
  http2: {
    akamai_fingerprint: string;
    settings: H2Setting[];
    window_update_increment: number;
    priority_frames: unknown[];
  };
}

async function captureChrome(): Promise<void> {
  const options = new chrome.Options();
  options.addArguments("--headless=new");
  options.setChromeBinaryPath("/usr/bin/google-chrome-stable");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    await driver.get(PEET_URL);
    const body = await driver.findElement(By.tagName("body"));
    const text = await body.getText();
    const data: PeetData = JSON.parse(text);
    printResult("Real Chrome (Selenium)", data);
  } finally {
    await driver.quit();
  }
}

async function captureFirefox(): Promise<void> {
  const options = new firefox.Options();
  options.addArguments("-headless");
  options.setBinary("/snap/firefox/current/usr/lib/firefox/firefox");
  options.setPreference("devtools.jsonview.enabled", false);
  const driver = await new Builder().forBrowser("firefox").setFirefoxOptions(options).build();

  try {
    await driver.get(PEET_URL);
    const body = await driver.findElement(By.tagName("body"));
    const text = await body.getText();
    const data: PeetData = JSON.parse(text);
    printResult("Real Firefox (Selenium)", data);
  } finally {
    await driver.quit();
  }
}

function printResult(label: string, data: PeetData): void {
  console.log(`=== ${label} ===`);
  console.log(`  HTTP version:   ${data.http_version}`);
  console.log(`  JA4:            ${data.tls?.ja4}`);
  console.log(`  Akamai h2 fp:   ${data.http2?.akamai_fingerprint}`);
  if (data.http2?.settings?.length) {
    console.log(`  H2 SETTINGS:`);
    for (const s of data.http2.settings) {
      console.log(`    ${s.id} = ${s.value}`);
    }
  }
  console.log(`  WINDOW_UPDATE:  ${data.http2?.window_update_increment}`);
  console.log(`  Priority frames: ${data.http2?.priority_frames?.length || 0}`);
  console.log();
}

async function main(): Promise<void> {
  console.log("Capturing real browser HTTP/2 fingerprints via tls.peet.ws\n");
  await captureChrome();
  await captureFirefox();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
