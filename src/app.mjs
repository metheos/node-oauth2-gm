import dotenv from "dotenv";
import * as readline from "node:readline/promises";
import { exit, stdin as input, stdout as output } from "node:process";
import fs from "fs";
import path from "path";
import os from "os"; // Added os import
import axios from "axios";
import { CookieJar } from "tough-cookie";
import { HttpCookieAgent, HttpsCookieAgent } from "http-cookie-agent/http";
import jwt from "jsonwebtoken";
import { TOTP } from "totp-generator";
import https from "https";
import { custom } from "openid-client";
import * as openidClient from "openid-client";
import unzipper from "unzipper";
// Dynamically import patchright after env is set
let chromium;

// Set up readline interface
const rl = readline.createInterface({ input, output });

// --- Chromium/FFMPEG auto-download logic ---
async function ensureChromiumAndFFMPEG() {
  const baseDir = path.resolve(path.dirname(process.execPath), "ms-playwright");
  const chromiumDir = path.join(baseDir, "chromium-1169");
  const ffmpegDir = path.join(baseDir, "ffmpeg-1011");
  const headlessDir = path.join(baseDir, "chromium_headless_shell-1169");
  const winlddDir = path.join(baseDir, "winldd-1007");
  const browsersJsonPath = path.join(baseDir, "browsers.json");

  const downloads = [
    {
      name: "Chromium",
      dir: chromiumDir,
      url: "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1169/chromium-win64.zip",
    },
    {
      name: "FFMPEG",
      dir: ffmpegDir,
      url: "https://cdn.playwright.dev/dbazure/download/playwright/builds/ffmpeg/1011/ffmpeg-win64.zip",
    },
    {
      name: "Chromium Headless Shell",
      dir: headlessDir,
      url: "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1169/chromium-headless-shell-win64.zip",
    },
    {
      name: "WinLDD",
      dir: winlddDir,
      url: "https://cdn.playwright.dev/dbazure/download/playwright/builds/winldd/1007/winldd-win64.zip",
    },
  ];

  for (const d of downloads) {
    if (!fs.existsSync(d.dir)) {
      console.log(`⬇️ Downloading ${d.name}...`);
      const zipPath = path.join(baseDir, `${d.name.replace(/ /g, "_")}.zip`);
      fs.mkdirSync(path.dirname(zipPath), { recursive: true });
      await downloadFile(d.url, zipPath);
      fs.mkdirSync(path.dirname(d.dir), { recursive: true });
      await extractZip(zipPath, d.dir);
      fs.unlinkSync(zipPath);
      console.log(`📁 ${d.name} downloaded and extracted.`);
    }
  }
  // Always ensure browsers.json exists for Playwright/Patchright
  const browsersJson = {
    chromium: {
      revision: "1169",
      executablePath: path.join(chromiumDir, "chrome-win", "chrome.exe"),
      downloadUrl: "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1169/chromium-win64.zip",
    },
  };
  fs.writeFileSync(browsersJsonPath, JSON.stringify(browsersJson, null, 2));
  console.log("📝 Created/updated browsers.json");

  // Debug: check what's actually in the chromium directory
  try {
    const chromiumContents = fs.readdirSync(chromiumDir);
    console.log("[DEBUG] chromium-1169 directory contents:", chromiumContents.slice(0, 10)); // Show first 10 items

    // Look for chrome.exe or chromium.exe
    const exeFiles = chromiumContents.filter((f) => f.endsWith(".exe"));
    console.log("[DEBUG] .exe files in chromium-1169:", exeFiles);

    // Check browsers.json content
    const browsersJsonContent = fs.readFileSync(browsersJsonPath, "utf8");
    console.log("[DEBUG] browsers.json content:", browsersJsonContent);
  } catch (e) {
    console.log("[DEBUG] Error reading chromium directory:", e.message);
  }
}

async function downloadFile(url, dest) {
  const writer = fs.createWriteStream(dest);
  const response = await axios({ url, method: "GET", responseType: "stream" });
  await new Promise((resolve, reject) => {
    response.data.pipe(writer);
    let error = null;
    writer.on("error", (err) => {
      error = err;
      writer.close();
      reject(err);
    });
    writer.on("close", () => {
      if (!error) resolve();
    });
  });
}

async function extractZip(zipPath, outDir) {
  await fs
    .createReadStream(zipPath)
    .pipe(unzipper.Extract({ path: outDir }))
    .promise();
}
// --- end auto-download logic ---

// Define variables
var user_email_addr = null;
var user_password = null;
var user_device_uuid = null;
var user_vehicle_vin = null;
var user_totp_key = null;

// GMAuth Class
class GMAuth {
  constructor(config) {
    this.config = config;
    this.config.tokenLocation = this.config.tokenLocation ?? "./";
    this.MSTokenPath = path.join(this.config.tokenLocation, "microsoft_tokens.json");
    this.GMTokenPath = path.join(this.config.tokenLocation, "gm_tokens.json");
    this.oidc = {
      Issuer: openidClient.Issuer,
      generators: openidClient.generators,
    };
    this.browser = null; // Added browser property
    this.context = null; // Added context property
    this.currentPage = null; // Added currentPage property
    this.capturedAuthCode = null; // Added capturedAuthCode property

    const modernCiphers = [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-CHACHA20_POLY1305",
      "ECDHE-RSA-CHACHA20_POLY1305",
      "ECDHE-RSA-AES128-SHA",
      "ECDHE-RSA-AES256-SHA",
      "AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "AES128-SHA",
      "AES256-SHA",
    ].join(":");

    https.globalAgent.options.ciphers = modernCiphers;
    https.globalAgent.options.minVersion = "TLSv1.2";

    this.jar = new CookieJar(undefined, {
      looseMode: true,
      rejectPublicSuffixes: false,
      allowSpecialUseDomain: true,
    });

    this.axiosClient = axios.create({
      httpAgent: new HttpCookieAgent({ cookies: { jar: this.jar } }),
      httpsAgent: new HttpsCookieAgent({
        cookies: { jar: this.jar },
        ciphers: modernCiphers,
        minVersion: "TLSv1.2",
        keepAlive: true,
      }),
      maxRedirects: 0,
      validateStatus: (status) => status >= 200 && status < 400,
    });
    this.csrfToken = null;
    this.transId = null;
    this.currentGMAPIToken = null;
    this.debugMode = true;
    this.loadCurrentGMAPIToken();
  }

  // Helper function to wait for authorization code
  async waitForAuthCode(timeoutMs = 10000, intervalMs = 500) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      if (this.capturedAuthCode) {
        console.log(
          `🪝 [waitForAuthCode] Auth code captured: ${this.capturedAuthCode.substring(0, 20)}${this.capturedAuthCode.length > 20 ? "..." : ""}`
        );
        return true;
      }
      // if (this.debugMode) console.log(`[waitForAuthCode] Waiting for auth code... ${(Date.now() - startTime) / 1000}s elapsed`);
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    // if (this.debugMode) console.log(`[waitForAuthCode] Timeout waiting for auth code after ${timeoutMs / 1000}s`);
    return false;
  }

  // Browser management methods (copied from GMAuth.ts)
  async initBrowser() {
    if (this.browser) {
      return; // Browser already initialized
    }

    const profilePath = path.join(os.tmpdir(), "gmauth-browser-profile");
    if (fs.existsSync(profilePath)) {
      fs.rmSync(profilePath, { recursive: true, force: true });
      if (this.debugMode) console.log("🗑️ Deleted existing temp browser profile at:", profilePath);
    }
    // Ensure the profile path parent directory exists, launchPersistentContext creates the final dir
    fs.mkdirSync(path.dirname(profilePath), { recursive: true });

    this.context = await chromium.launchPersistentContext(
      profilePath, // Use user-specific temp directory
      {
        channel: "chromium",
        headless: true, // Consider making this configurable via debugMode
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        viewport: { width: 1920, height: 1080 },
        args: ["--no-first-run", "--disable-default-browser-check", "--start-maximized"],
      }
    );

    this.browser = this.context.browser();

    await this.context.addInitScript(() => {
      Object.defineProperty(navigator, "webdriver", {
        get: () => undefined,
      });
    });

    if (this.debugMode) console.log(`🌐 Browser initialized with persistent context`);
  }

  async closeBrowser() {
    if (this.currentPage) {
      await this.currentPage.close();
      this.currentPage = null;
    }
    if (this.context) {
      await this.context.close();
      this.context = null;
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
    this.capturedAuthCode = null;
  }

  async authenticate() {
    try {
      let loadedTokenSet = await this.loadMSToken();
      if (loadedTokenSet !== false) {
        if (this.debugMode) console.log("📂 Using existing MS tokens");
        return await this.getGMAPIToken(loadedTokenSet);
      }

      if (this.debugMode) console.log("🤖 Performing full authentication");
      await this.doFullAuthSequence();
      loadedTokenSet = await this.loadMSToken();
      if (!loadedTokenSet) {
        throw new Error("🚫 Failed to load MS token set and could not generate a new one");
      }
      return await this.getGMAPIToken(loadedTokenSet);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.handleRequestError(error);
      } else {
        console.error("🚫 Authentication failed:", error);
      }
      throw error;
    }
  }

  async doFullAuthSequence() {
    try {
      // Added try/finally block
      this.capturedAuthCode = null; // Reset captured auth code

      const { authorizationUrl, code_verifier } = await this.startMSAuthorizationFlow();

      await this.submitCredentials(authorizationUrl); // Pass authorizationUrl

      // Attempt to wait for auth code if not immediately available from submitCredentials' CDP listener
      if (!this.capturedAuthCode) {
        if (this.debugMode) {
          console.log("⌛ [doFullAuthSequence] Auth code not immediately set after submitCredentials. Waiting...");
        }
        await this.waitForAuthCode(10000); // Wait up to 10 seconds
      }

      // If code still not captured, try MFA (which also attempts to capture code)
      if (!this.capturedAuthCode) {
        if (this.debugMode) console.log("🕵️ [doFullAuthSequence] Auth code not captured after initial wait. Proceeding to handleMFA.");
        await this.handleMFA();
      }

      // One final check if MFA was called and might have set it, or if previous waits were on the edge
      if (!this.capturedAuthCode) {
        if (this.debugMode) console.log("⌛ [doFullAuthSequence] Auth code still not captured after MFA attempt. Performing a final short wait.");
        await this.waitForAuthCode(5000); // Shorter final wait
      }

      const authCode = await this.getAuthorizationCode();
      if (!authCode) {
        throw new Error(
          "🚫 Failed to get authorization code after all attempts. Possible incorrect credentials, MFA issue, or unexpected page flow."
        );
      }

      const tokenSet = await this.getMSToken(authCode, code_verifier);
      await this.saveTokens(tokenSet);
      return tokenSet;
    } finally {
      // Added finally block
      await this.closeBrowser(); // Ensure browser is closed
    }
  }

  async saveTokens(tokenSet) {
    if (this.debugMode) console.log("💾 Saving MS tokens to ", this.MSTokenPath);
    fs.writeFileSync(this.MSTokenPath, JSON.stringify(tokenSet));

    if (this.currentGMAPIToken) {
      if (this.debugMode) console.log("💾 Saving GM tokens to ", this.GMTokenPath);
      fs.writeFileSync(this.GMTokenPath, JSON.stringify(this.currentGMAPIToken));
    }
  }

  async getAuthorizationCode() {
    // Return the authorization code captured during the browser flow
    if (this.capturedAuthCode) {
      if (this.debugMode) console.log("✅ Using authorization code captured from browser redirect");
      return this.capturedAuthCode;
    }
  }

  async handleMFA() {
    if (this.debugMode) console.log("🤖 Handling MFA via browser automation");

    if (!this.context || !this.currentPage) {
      throw new Error("🚫 Browser context and page not initialized - call submitCredentials first");
    }
    const page = this.currentPage;

    try {
      await page.waitForLoadState("networkidle");
      await page.waitForSelector('input[name="otpCode"], input[name="emailMfa"], input[id="verificationCode"]', { timeout: 10000 });

      const pageContent = await page.content();
      let mfaType = null;
      if ((await page.locator('input[name="otpCode"]').count()) > 0 || pageContent.includes("otpCode")) {
        mfaType = "TOTP";
      } else if ((await page.locator('input[name="emailMfa"]').count()) > 0 || pageContent.includes("emailMfa")) {
        mfaType = "EMAIL";
      } else if ((await page.locator('input[id="verificationCode"]').count()) > 0 || pageContent.includes("verificationCode")) {
        mfaType = "SMS";
      }

      if (this.debugMode) console.log("✅ Determined MFA Type is", mfaType);
      if (mfaType == null) {
        throw new Error("🚫 Could not determine MFA Type. Bad email or password?");
      }

      // Set up CDP session to capture auth code redirects
      const client = await page.context().newCDPSession(page);
      await client.send("Network.enable");

      client.on("Network.requestWillBeSent", (params) => {
        const requestUrl = params.request.url;
        // if (this.debugMode) {
        //   console.log(`[DEBUG handleMFA CDP requestWillBeSent] Request to: ${requestUrl.substring(0, 100)}${requestUrl.length > 100 ? "..." : ""}`);
        // }
        if (requestUrl.toLowerCase().startsWith("msauth.com.gm.mychevrolet://auth")) {
          if (this.debugMode)
            console.log(
              `✅ [SUCCESS handleMFA CDP requestWillBeSent] Captured msauth redirect via CDP. URL: ${requestUrl.substring(0, 100)}${
                requestUrl.length > 100 ? "..." : ""
              }`
            );
          this.capturedAuthCode = this.getRegexMatch(requestUrl, `[?&]code=([^&]*)`);
          if (this.capturedAuthCode) {
            if (this.debugMode)
              console.log(
                `✅ [SUCCESS handleMFA CDP requestWillBeSent] Extracted authorization code: ${this.capturedAuthCode.substring(0, 20)}${
                  this.capturedAuthCode.length > 20 ? "..." : ""
                }`
              );
          } else {
            console.error(`🚫 [ERROR handleMFA CDP requestWillBeSent] msauth redirect found, but FAILED to extract code from: ${requestUrl}`);
          }
        }
      });

      // client.on("Network.responseReceived", (params) => {
      //   const response = params.response;
      //   if ((response.status === 301 || response.status === 302) && response.headers && response.headers.location) {
      //     const location = response.headers.location;
      //     if (this.debugMode) {
      //       console.log(
      //         `[DEBUG handleMFA CDP responseReceived] Redirect from ${response.url} to: ${location.substring(0, 100)}${
      //           location.length > 100 ? "..." : ""
      //         }`
      //       );
      //     }
      //     if (location.toLowerCase().startsWith("msauth.com.gm.mychevrolet://auth")) {
      //       if (this.debugMode)
      //         console.log(
      //           `[SUCCESS handleMFA CDP responseReceived] Captured msauth redirect via CDP response. Location: ${location.substring(0, 100)}${
      //             location.length > 100 ? "..." : ""
      //           }`
      //         );
      //       this.capturedAuthCode = this.getRegexMatch(location, `[?&]code=([^&]*)`);
      //       if (this.capturedAuthCode) {
      //         if (this.debugMode)
      //           console.log(
      //             `[SUCCESS handleMFA CDP responseReceived] Extracted authorization code: ${this.capturedAuthCode.substring(0, 20)}${
      //               this.capturedAuthCode.length > 20 ? "..." : ""
      //             }`
      //           );
      //       } else {
      //         console.error(`[ERROR handleMFA CDP responseReceived] msauth redirect found, but FAILED to extract code from: ${location}`);
      //       }
      //     }
      //   }
      // });

      if (mfaType === "SMS") {
        mfaCode = await rl.question("⌨ Enter MFA Code from SMS:");

        const smsField = await page
          .locator('input[id="verificationCode"], [aria-label*="Verification Code"i], [aria-label*="Verification Code"i]')
          .first();
        await smsField.fill(mfaCode);

        const submitMfaButton = await page
          .locator(
            'button[type="submit"], input[type="submit"], button:has-text("Verify"), button:has-text("Continue"), button:has-text("Submit"), [role="button"][aria-label*="Verify"i], [role="button"][aria-label*="Continue"i], [role="button"][aria-label*="Submit"i]'
          )
          .first();
        if (this.debugMode) console.log("🖱️ Submitting SMS MFA Code:", mfaCode);
        await submitMfaButton.click();
      } else if (mfaType === "TOTP") {
        var mfaCode = "";
        if (user_totp_key && user_totp_key.trim() != "" && user_totp_key.length >= 16) {
          var totp_secret = user_totp_key;
          if (user_totp_key.includes("secret=")) {
            totp_secret = this.getRegexMatch(user_totp_key, "secret=(.*?)&");
          }
          const { otp } = TOTP.generate(totp_secret, {
            digits: 6,
            algorithm: "SHA-1",
            period: 30,
          });
          if (this.debugMode) console.log("🤖 Generating and submitting OTP code:", otp);
          mfaCode = otp;
        } else {
          mfaCode = await rl.question("⌨ Enter MFA Code from Authenticator App:");
        }

        const otpField = await page.locator('input[name="otpCode"], [aria-label*="One-Time Passcode"i], [aria-label*="OTP"i]').first();
        await otpField.fill(mfaCode);

        const submitMfaButton = await page
          .locator(
            'button[type="submit"], input[type="submit"], button:has-text("Verify"), button:has-text("Continue"), button:has-text("Submit"), [role="button"][aria-label*="Verify"i], [role="button"][aria-label*="Continue"i], [role="button"][aria-label*="Submit"i]'
          )
          .first();
        if (this.debugMode) console.log("🖱️ Submitting OTP Code:", mfaCode);
        await submitMfaButton.click();
      } else if (mfaType === "EMAIL") {
        mfaCode = await rl.question("⌨ Enter MFA Code from EMAIL:");

        const emailField = await page
          .locator('input[id="verificationCode"], [aria-label*="Verification Code"i], [aria-label*="Verification Code"i]')
          .first();
        await emailField.fill(mfaCode);

        const submitMfaButton = await page
          .locator(
            'button[type="submit"], input[type="submit"], button:has-text("Verify"), button:has-text("Continue"), button:has-text("Submit"), [role="button"][aria-label*="Verify"i], [role="button"][aria-label*="Continue"i], [role="button"][aria-label*="Submit"i]'
          )
          .first();
        if (this.debugMode) console.log("🖱️ Submitting EMAIL MFA Code:", mfaCode);
        await submitMfaButton.click();
      }

      try {
        // Wait for the auth code to be captured by CDP listeners
        if (this.debugMode) console.log("⌛ [handleMFA TOTP] Waiting for auth code capture after submit...");
        const captured = await this.waitForAuthCode(); // Use the new helper
        if (!captured && this.debugMode) {
          console.log("🚫 [handleMFA TOTP] Did not capture auth code after submit within timeout.");
        }
      } catch (e) {
        console.error("🚫 [handleMFA TOTP] Error during waitForAuthCode:", e);
      }

      try {
        await client.detach();
      } catch (e) {
        // CDP session might already be detached
      }
      if (this.debugMode) console.log("⌛ Waiting for redirect after MFA submission...");
      await page.waitForLoadState("networkidle");

      if (this.capturedAuthCode) {
        if (this.debugMode) console.log("✅ Successfully captured authorization code");
      } else {
        if (this.debugMode) console.log("🚫 Failed to capture authorization code from browser redirect");
      }
    } catch (error) {
      console.error("🚫 Error in handleMFA:", error);
      throw error;
    }
  }

  async submitCredentials(authorizationUrl) {
    if (this.debugMode) console.log("✅ Starting browser-based authentication");
    try {
      await this.initBrowser();
    } catch (error) {
      console.log("🫥 Chromium not found. Downloading");
      try {
        await ensureChromiumAndFFMPEG();
        await this.initBrowser();
      } catch (err) {
        throw new Error(`🚫 Failed to download and initialize Chromium: ${err.message}`);
      }
    }
    if (!this.context) {
      throw new Error("🚫 Browser context not initialized");
    }

    const page = await this.context.newPage();
    this.currentPage = page;

    const client = await page.context().newCDPSession(page);
    await client.send("Network.enable");

    client.on("Network.requestWillBeSent", (params) => {
      const requestUrl = params.request.url;
      if (this.debugMode) {
        // console.log(
        //   `[DEBUG submitCredentials CDP requestWillBeSent] Request to: ${requestUrl.substring(0, 100)}${requestUrl.length > 100 ? "..." : ""}`
        // );
      }
      if (requestUrl.toLowerCase().startsWith("msauth.com.gm.mychevrolet://auth")) {
        if (this.debugMode)
          console.log(
            `✅ [SUCCESS submitCredentials CDP requestWillBeSent] Captured msauth redirect via CDP. URL: ${requestUrl.substring(0, 100)}${
              requestUrl.length > 100 ? "..." : ""
            }`
          );
        this.capturedAuthCode = this.getRegexMatch(requestUrl, `[?&]code=([^&]*)`);
        if (this.capturedAuthCode) {
          if (this.debugMode)
            console.log(
              `✅ [SUCCESS submitCredentials CDP requestWillBeSent] Extracted authorization code: ${this.capturedAuthCode.substring(0, 20)}${
                this.capturedAuthCode.length > 20 ? "..." : ""
              }`
            );
        } else {
          console.error(
            `🚫 [ERROR submitCredentials CDP requestWillBeSent] msauth redirect found, but FAILED to extract code from: ${requestUrl.substring(
              0,
              100
            )}${requestUrl.length > 100 ? "..." : ""}`
          );
        }
      }
    });

    // client.on("Network.responseReceived", (params) => {
    //   const response = params.response;
    //   if ((response.status === 301 || response.status === 302) && response.headers && response.headers.location) {
    //     const location = response.headers.location;
    //     if (this.debugMode) {
    //       console.log(
    //         `[DEBUG submitCredentials CDP responseReceived] Redirect from ${response.url} to: ${location.substring(0, 100)}${
    //           location.length > 100 ? "..." : ""
    //         }`
    //       );
    //     }

    //     if (location.toLowerCase().startsWith("msauth.com.gm.mychevrolet://auth")) {
    //       if (this.debugMode)
    //         console.log(
    //           `[SUCCESS submitCredentials CDP responseReceived] Captured msauth redirect via CDP response. Location: ${location.substring(0, 100)}${
    //             location.length > 100 ? "..." : ""
    //           }`
    //         );
    //       this.capturedAuthCode = this.getRegexMatch(location, `[?&]code=([^&]*)`);
    //       if (this.capturedAuthCode) {
    //         if (this.debugMode)
    //           console.log(
    //             `[SUCCESS submitCredentials CDP responseReceived] Extracted authorization code: ${this.capturedAuthCode.substring(0, 20)}${
    //               this.capturedAuthCode.length > 20 ? "..." : ""
    //             }`
    //           );
    //       } else {
    //         console.error(
    //           `[ERROR submitCredentials CDP responseReceived] msauth redirect found, but FAILED to extract code from: ${location.substring(0, 100)}${
    //             location.length > 100 ? "..." : ""
    //           }`
    //         );
    //       }
    //     }
    //   }
    // });

    try {
      if (this.debugMode) console.log(`🌐 Navigating to authorization URL: ${authorizationUrl}`);
      await page.goto(authorizationUrl, { waitUntil: "networkidle" });
      await page.waitForLoadState("networkidle");

      if (this.debugMode) console.log("⌨️ Attempting to fill username");
      await page.fill('input[type="email"]', this.config.username);

      if (this.debugMode) console.log("🖱️ Attempting to click next/submit after username");
      const nextButtonSelectors = [
        'button#continue[data-dtm="sign in"][aria-label="Continue"]',
        'button:has-text("Continue")[data-dtm="sign in"]',
        '[role="button"][aria-label*="Continue"i]',
        'button#continue[data-dtm="sign in"][aria-label="Sign in"]',
        'button:has-text("Log In")[data-dtm="sign in"]',
        'button:has-text("Sign in")[data-dtm="sign in"]',
        '[role="button"][aria-label*="Sign in"i]',
        '[role="button"][aria-label*="Log In"i]',
      ];
      let clickedNext = false;
      for (const selector of nextButtonSelectors) {
        try {
          await page.locator(selector).first().click({ timeout: 5000 });
          if (this.debugMode) console.log(`🖱️ Clicked "${selector}" after username`);
          clickedNext = true;
          break;
        } catch (e) {
          // Selector not found or not clickable, try next
        }
      }
      if (!clickedNext) {
        console.warn("🚫 Could not find or click a 'Next' or 'Sign In' button after filling username.");
      }
      await page.waitForLoadState("networkidle");

      // Check if the page creates element: <span class="chevy-top-error2 gb-body2 top-error-msg2">Invalid login credentials. Please try again.</span>
      await page.waitForTimeout(1000); // Wait a moment for error to appear if it's going to
      const isErrorVisible = await page
        .locator('.top-error-msg2:has-text("Invalid login credentials")')
        .isVisible()
        .catch(() => false);

      if (isErrorVisible) {
        console.log("🚫 Invalid login credentials detected after submitting username.");
        console.log("❗ Please check your username/email and try again.");
        exit(1);
      }

      if (this.debugMode) console.log("⌨️ Attempting to fill password");
      await page.fill('input[type="password"]', this.config.password);

      if (this.debugMode) console.log("🖱️ Attempting to click next/submit after password");
      clickedNext = false;
      for (const selector of nextButtonSelectors) {
        try {
          await page.locator(selector).first().click({ timeout: 5000 });
          if (this.debugMode) console.log(`🖱️ Clicked "${selector}" after password`);
          clickedNext = true;
          break;
        } catch (e) {
          // Selector not found or not clickable, try next
        }
      }
      if (!clickedNext) {
        console.warn("🚫 Could not find or click a 'Next' or 'Sign In' button after filling password.");
      }

      if (this.debugMode) console.log("⌛ Waiting for navigation after credential submission...");
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      if (this.capturedAuthCode) {
        if (this.debugMode) console.log("✅ Authorization code captured during submitCredentials.");
        return;
      }

      // const urlAfterLogin = page.url();
      // if (this.debugMode) console.log("URL after login attempt:", urlAfterLogin);

      // const isMfaPage = await page.isVisible('input[name="otpCode"], input[name="emailMfa"], input[id="verificationCode"]');
      // if (isMfaPage) {
      //   if (this.debugMode) console.log("MFA page detected after credential submission.");
      // } else if (!this.capturedAuthCode) {
      //   console.warn("Did not capture auth code and not on a recognized MFA page after login. Current URL:", urlAfterLogin);
      // }
    } catch (error) {
      console.error("🚫 Error in submitCredentials:", error);
      if (error.message && error.message.includes("Timeout")) {
        console.error("⌛ Timeout occurred. Current page URL:", page.url());
        const content = await page.content();
        console.error("🌐 Page content:", content.substring(0, 500));
      }
      try {
        if (client && !client.isClosed()) {
          await client.detach();
        }
      } catch (detachError) {
        console.warn("🚫 Error detaching CDP client in submitCredentials error handler:", detachError);
      }
      throw error;
    }
    try {
      if (client && !client.isClosed()) {
        await client.detach();
      }
    } catch (detachError) {
      // console.warn("Error detaching CDP client at end of submitCredentials:", detachError);
    }
  }

  static GMAuthTokenIsValid(authToken) {
    return authToken && authToken.expires_at && authToken.expires_at > Date.now() / 1000 + 5 * 60;
  }

  async loadCurrentGMAPIToken() {
    if (this.debugMode) console.log("📂 Loading existing GM API token, if it exists.");
    if (fs.existsSync(this.GMTokenPath)) {
      try {
        const storedToken = JSON.parse(fs.readFileSync(this.GMTokenPath, "utf-8"));
        const decodedPayload = jwt.decode(storedToken.access_token);

        if (!decodedPayload || decodedPayload?.uid?.toUpperCase() !== this.config.username.toUpperCase()) {
          if (this.debugMode) console.log("🕵️ Stored GM API token was for different user, getting new token");
        } else {
          const now = Math.floor(Date.now() / 1000);
          if (storedToken.expires_at && storedToken.expires_at > now + 5 * 60) {
            if (this.debugMode) console.log("✅ Loaded existing GM API token");
            this.currentGMAPIToken = storedToken;
          } else {
            if (this.debugMode) console.log("⏰ Existing GM API token has expired");
          }
        }
      } catch (err) {
        console.warn("🚫 Stored GM API token was not parseable or invalid, getting new token:", err.message);
      }
    } else {
      if (this.debugMode) console.log("🫥 No existing GM API token file found.");
    }
  }

  async getGMAPIToken(tokenSet) {
    const now = Math.floor(Date.now() / 1000);
    if (this.currentGMAPIToken && this.currentGMAPIToken.expires_at > now + 5 * 60) {
      if (this.debugMode) console.log("✅ Returning existing valid GM API token");
      return this.currentGMAPIToken;
    }

    if (this.debugMode) console.log("🛂 Requesting GM API Token using MS Access Token");
    const url = "https://na-mobile-api.gm.com/sec/authz/v3/oauth/token";
    try {
      const response = await this.axiosClient.post(
        url,
        new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: tokenSet.access_token,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
          scope: "msso role_owner priv onstar gmoc user user_trailer",
          device_id: this.config.deviceId,
        }).toString(),
        {
          withCredentials: true,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            accept: "application/json",
          },
        }
      );

      const gmapiTokenResponse = response.data;
      const decodedPayload = jwt.decode(gmapiTokenResponse.access_token);
      if (!decodedPayload?.vehs) {
        console.warn("🚫 Returned GM API token was missing vehicle information. Please check if you used the right GM account or try again later.");
        // if (fs.existsSync(this.MSTokenPath)) fs.renameSync(this.MSTokenPath, `${this.MSTokenPath}.old`);
        // if (fs.existsSync(this.GMTokenPath)) fs.renameSync(this.GMTokenPath, `${this.GMTokenPath}.old`);
        // this.currentGMAPIToken = null;
        // return await this.authenticate();
        // quit the program
        exit(1);
      }

      gmapiTokenResponse.expires_at = Math.floor(Date.now() / 1000) + parseInt(gmapiTokenResponse.expires_in.toString());
      gmapiTokenResponse.expires_in = parseInt(gmapiTokenResponse.expires_in.toString());

      if (this.debugMode) console.log("⏰ Set GM Token expiration to ", gmapiTokenResponse.expires_at);

      this.currentGMAPIToken = gmapiTokenResponse;
      await this.saveTokens(tokenSet);
      return gmapiTokenResponse;
    } catch (error) {
      this.handleRequestError(error, "🚫 GM API Token Error");
      throw error;
    }
  }

  processCookieHeaders(response, url) {
    const setCookieHeaders = response.headers["set-cookie"];
    if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
      setCookieHeaders.forEach((cookieString) => {
        const parsedUrl = new URL(url);
        try {
          this.jar.setCookieSync(cookieString, parsedUrl.origin);
          if (this.debugMode) console.log(`🍪 Added cookie: ${cookieString.split(";")[0]}`);
        } catch (error) {
          console.error(`🚫 Failed to add cookie: ${cookieString} for URL ${parsedUrl.origin}, Error: ${error.message}`);
        }
      });
    }
  }

  async getRequest(url) {
    try {
      const cookieStringBefore = await this.jar.getCookieString(url);
      if (this.debugMode) {
        console.log("🍪 Cookies before GET:", cookieStringBefore);
        console.log("🌐 GET URL:", url);
      }
      const response = await this.axiosClient.get(url, {
        withCredentials: true,
        maxRedirects: 0,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "gzip, deflate, br",
          "Accept-Language": "en-US,en;q=0.9",
          Connection: "keep-alive",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.6 Mobile/15E148 Safari/604.1",
          ...(cookieStringBefore && { Cookie: cookieStringBefore }),
        },
      });
      this.processCookieHeaders(response, url);
      if (this.debugMode) console.log("🌐 GET Response status:", response.status, "for URL:", url);
      return response;
    } catch (error) {
      if (error.response && error.response.status !== 302) {
        this.handleRequestError(error, "🚫 GET Request Error");
      } else if (!error.response) {
        console.error("🚫 GET Request failed without response:", error.message);
      }
      return (
        error.response || {
          status: error.code,
          data: error.message,
          headers: {},
        }
      );
    }
  }

  async postRequest(url, postData, csrfToken) {
    try {
      const formData = new URLSearchParams();
      for (const [key, value] of Object.entries(postData)) {
        formData.append(key, value);
      }
      const cookieString = await this.jar.getCookieString(url);
      if (this.debugMode) {
        console.log("🍪 Cookies before POST:", cookieString);
        console.log("🌐 POST URL:", url);
        console.log("🌐 POST data:", formData.toString());
      }
      const response = await this.axiosClient.post(url, formData.toString(), {
        withCredentials: true,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          Accept: "application/json, text/javascript, */*; q=0.01",
          "Accept-Language": "en-US,en;q=0.9",
          Origin: "https://custlogin.gm.com",
          "x-csrf-token": csrfToken,
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.6 Mobile/15E148 Safari/604.1",
          "X-Requested-With": "XMLHttpRequest",
          Connection: "keep-alive",
          ...(cookieString && { Cookie: cookieString }),
        },
      });
      this.processCookieHeaders(response, url);
      if (this.debugMode) console.log("🌐 POST Response status:", response.status, "for URL:", url);
      return response;
    } catch (error) {
      this.handleRequestError(error, "🌐 POST Request Error");
      if (error.response) return error.response;
      throw error;
    }
  }

  handleRequestError(error, context = "HTTP Error") {
    if (error.response) {
      console.error(`${context} ${error.response.status}: ${error.response.statusText}`);
      console.error("Error details:", error.response.data);
      if (error.response.status === 401) {
        console.error("🚫 Authentication failed. Please check your credentials or token validity.");
      }
    } else if (error.request) {
      console.error(`${context}: No response received from server`);
    } else {
      console.error(`${context}: Request setup error - ${error.message}`);
    }
  }

  getRegexMatch(haystack, regexString) {
    const re = new RegExp(regexString);
    const r = haystack.match(re);
    return r ? r[1] : null;
  }

  async setupOpenIDClient() {
    const fallbackConfig = {
      issuer: "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/",
      authorization_endpoint: "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/authorize",
      token_endpoint: "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/token",
      jwks_uri: "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/discovery/v2.0/keys",
      response_types_supported: ["code", "id_token", "code id_token"],
      response_modes_supported: ["query", "fragment", "form_post"],
      grant_types_supported: ["authorization_code", "implicit", "refresh_token"],
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid"],
    };
    let issuerInstance = null;
    try {
      const discoveryUrl =
        "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/.well-known/openid-configuration";
      if (this.debugMode) console.log("🔍 Attempting OpenID discovery from:", discoveryUrl);

      const response = await axios.get(discoveryUrl, {
        headers: {
          Accept: "application/json",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.6 Mobile/15E148 Safari/604.1",
        },
        timeout: 10000,
      });
      const discoveredConfig = response.data;
      issuerInstance = new this.oidc.Issuer({
        ...fallbackConfig,
        ...discoveredConfig,
        authorization_endpoint: discoveredConfig.authorization_endpoint || fallbackConfig.authorization_endpoint,
        token_endpoint: discoveredConfig.token_endpoint || fallbackConfig.token_endpoint,
        jwks_uri: discoveredConfig.jwks_uri || fallbackConfig.jwks_uri,
      });
      if (this.debugMode) console.log("✅ Successfully created issuer with discovery data");
    } catch (error) {
      console.warn("OpenID discovery failed, using fallback configuration", error.message);
      issuerInstance = new this.oidc.Issuer(fallbackConfig);
      if (this.debugMode) console.log("✔️ Created issuer with fallback configuration");
    }
    if (!issuerInstance) throw new Error("🚫 Failed to create OpenID issuer");
    if (!issuerInstance.authorization_endpoint) throw new Error("🚫 Issuer missing authorization_endpoint");

    const client = new issuerInstance.Client({
      client_id: "3ff30506-d242-4bed-835b-422bf992622e",
      redirect_uris: ["msauth.com.gm.myChevrolet://auth"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    client[custom.clock_tolerance] = 5;
    return client;
  }

  async startMSAuthorizationFlow() {
    if (this.debugMode) console.log("😎 Starting PKCE auth");
    const client = await this.setupOpenIDClient();
    const code_verifier = this.oidc.generators.codeVerifier();
    const code_challenge = this.oidc.generators.codeChallenge(code_verifier);
    const state = this.oidc.generators.nonce();
    const authorizationUrl = client.authorizationUrl({
      scope: "https://gmb2cprod.onmicrosoft.com/3ff30506-d242-4bed-835b-422bf992622e/Test.Read openid profile offline_access",
      code_challenge,
      code_challenge_method: "S256",
      bundleID: "com.gm.myChevrolet",
      client_id: "3ff30506-d242-4bed-835b-422bf992622e",
      mode: "dark",
      evar25: "mobile_mychevrolet_chevrolet_us_app_launcher_sign_in_or_create_account",
      channel: "lightreg",
      ui_locales: "en-US",
      brand: "chevrolet",
      state,
    });
    return { authorizationUrl, code_verifier };
  }

  async getMSToken(code, code_verifier) {
    const client = await this.setupOpenIDClient();
    try {
      const openIdTokenSet = await client.callback("msauth.com.gm.myChevrolet://auth", { code }, { code_verifier, response_type: "code" });
      if (!openIdTokenSet.access_token) throw new Error("🚫 No access token received");

      const tokenSet = {
        access_token: openIdTokenSet.access_token,
        id_token: openIdTokenSet.id_token,
        refresh_token: openIdTokenSet.refresh_token,
        expires_at: openIdTokenSet.expires_at,
        expires_in: openIdTokenSet.expires_in,
      };
      if (this.debugMode) console.log("✅ MS Access Token obtained.");
      return tokenSet;
    } catch (err) {
      console.error("🚫 Failed to obtain MS access token:", err);
      throw err;
    }
  }

  async loadMSToken() {
    if (this.debugMode) console.log("📂 Loading existing MS tokens, if they exist.");
    if (fs.existsSync(this.MSTokenPath)) {
      let storedTokens = null;
      try {
        storedTokens = JSON.parse(fs.readFileSync(this.MSTokenPath, "utf-8"));
      } catch (err) {
        console.warn("🥲 Stored MS token was not parseable, getting new token:", err.message);
        return false;
      }

      try {
        const decodedPayload = jwt.decode(storedTokens.access_token);
        const usernameUpper = this.config.username.toUpperCase();
        const tokenUserIdentifier = decodedPayload?.name?.toUpperCase() || decodedPayload?.email?.toUpperCase() || decodedPayload?.upn?.toUpperCase();

        if (!decodedPayload || tokenUserIdentifier !== usernameUpper) {
          if (this.debugMode)
            console.log(`🕵️ Stored MS token was for different user (${tokenUserIdentifier} vs ${usernameUpper}), getting new token`);
          return false;
        }
      } catch (jwtError) {
        console.warn("🚫 Error decoding stored MS token, getting new token:", jwtError.message);
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      if (storedTokens.expires_at && storedTokens.expires_at > now + 5 * 60) {
        if (this.debugMode) console.log("✅ MS Access token is still valid");
        return storedTokens;
      } else if (storedTokens.refresh_token) {
        if (this.debugMode) console.log("🔃 Refreshing MS access token");
        try {
          const client = await this.setupOpenIDClient();
          const refreshedTokens = await client.refresh(storedTokens.refresh_token);
          if (!refreshedTokens.access_token) throw new Error("🚫 Refresh token response missing access_token");

          const tokenSet = {
            access_token: refreshedTokens.access_token,
            id_token: refreshedTokens.id_token,
            refresh_token: refreshedTokens.refresh_token || storedTokens.refresh_token,
            expires_at: refreshedTokens.expires_at,
            expires_in: refreshedTokens.expires_in,
          };
          await this.saveTokens(tokenSet);
          return tokenSet;
        } catch (refreshError) {
          console.error("🚫 Failed to refresh MS token:", refreshError.message);
          if (refreshError.data) console.error("🚫 Refresh error data:", refreshError.data);
          return false;
        }
      } else {
        if (this.debugMode) console.log("🚫 MS Token expired and no refresh token available.");
        return false;
      }
    }
    return false;
  }
}

// Wrap the main logic in an async function
async function main() {
  // Set env variable
  const msPlaywrightPath = path.resolve(path.dirname(process.execPath), "ms-playwright");
  process.env.PLAYWRIGHT_BROWSERS_PATH = msPlaywrightPath;
  console.log("[DEBUG] PLAYWRIGHT_BROWSERS_PATH:", msPlaywrightPath);
  try {
    const contents = fs.readdirSync(msPlaywrightPath);
    console.log("[DEBUG] ms-playwright directory contents:", contents);
  } catch (e) {
    console.log("[DEBUG] ms-playwright directory not found:", msPlaywrightPath);
  } // Dynamic import
  ({ chromium } = await import("patchright"));

  dotenv.config();
  user_email_addr = process.env.EMAIL ?? (await rl.question("📨 Enter OnStar account email address:"));
  user_password = process.env.PASSWORD ?? (await rl.question("🔑 Enter OnStar account password:"));
  user_vehicle_vin = process.env.VIN ?? (await rl.question("🚗 Enter Vehicle VIN (Optional, but testing will be skipped!):"));
  user_totp_key = process.env.TOTPKEY ?? (await rl.question("🔐 Enter TOTP Key/Secret (optional):"));
  user_device_uuid = process.env.UUID ?? (await rl.question("🔢 Enter Device ID (UUID) or press Enter to generate one:"));
  if (!user_device_uuid || user_device_uuid.trim() === "") {
    // Generate a v4 UUID
    user_device_uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0,
        v = c == "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
    console.log(`📱 Generated Device UUID: ${user_device_uuid}`);
    console.log(`💾 IMPORTANT: Save this UUID for future use in your applications!`);
    await rl.question("👍 Press Enter to continue after saving your UUID...");
  }

  if (!user_email_addr || !user_password || !user_device_uuid) {
    console.log("🚫 Onstar Account Information (Email, Password, Device ID) must be provided.");
    exit();
  }

  const gmAuthConfig = {
    username: user_email_addr,
    password: user_password,
    deviceId: user_device_uuid,
    totpKey: user_totp_key,
    tokenLocation: "./",
  };
  const gmAuth = new GMAuth(gmAuthConfig);

  try {
    console.log("🚘 Starting GM authentication process...");
    const gmapiTokenResponse = await gmAuth.authenticate();

    if (gmapiTokenResponse && gmapiTokenResponse.access_token) {
      console.log("✅ GM Authentication successful. GM API Token obtained.");
      console.log("✅ GM API Access Token (first 10 chars):", gmapiTokenResponse.access_token.substring(0, 10) + "...");
      console.log("📅 GM API Token Expires At:", new Date(gmapiTokenResponse.expires_at * 1000));

      if (user_vehicle_vin) {
        try {
          console.log(`🧪 Testing GM API Request for VIN: ${user_vehicle_vin}`);
          await testGMAPIRequestUsingAxios(gmapiTokenResponse, user_vehicle_vin, gmAuth.axiosClient);
        } catch (error) {
          console.error("🚫 GM API Test failed:", error.message);
        }
      } else {
        console.log("🦘 VIN not provided, skipping API test request.");
      }
    } else {
      console.error("🚫 GM Authentication failed to return a valid token.");
    }
  } catch (error) {
    console.error("🚫 Overall authentication or API test process failed:", error.message);
    if (error.stack) console.error(error.stack);
  }
  // Wait for user to press Enter before exiting
  await rl.question("Press Enter to exit...");
  exit();
}

// Test the GM API using the GM API token (rewritten for Axios)
async function testGMAPIRequestUsingAxios(gmapiTokenResponse, vin, axiosInstance) {
  console.log("🧪 Testing GM API Request with Axios");
  try {
    const postData = {
      diagnosticsRequest: {
        diagnosticItem: [
          "TARGET CHARGE LEVEL SETTINGS",
          "LAST TRIP FUEL ECONOMY",
          "PREF CHARGING TIMES SETTING",
          "ENERGY EFFICIENCY",
          "LIFETIME ENERGY USED",
          "ESTIMATED CABIN TEMPERATURE",
          "EV BATTERY LEVEL",
          "HV BATTERY CHARGE COMPLETE TIME",
          "HIGH VOLTAGE BATTERY PRECONDITIONING STATUS",
          "EV PLUG VOLTAGE",
          "HOTSPOT CONFIG",
          "ODOMETER",
          "HOTSPOT STATUS",
          "LIFETIME EV ODOMETER",
          "CHARGER POWER LEVEL",
          "CABIN PRECONDITIONING TEMP CUSTOM SETTING",
          "EV PLUG STATE",
          "EV CHARGE STATE",
          "TIRE PRESSURE",
          "LOCATION BASE CHARGE SETTING",
          "LAST TRIP DISTANCE",
          "CABIN PRECONDITIONING REQUEST",
          "GET COMMUTE SCHEDULE",
          "GET CHARGE MODE",
          "PREF CHARGING TIMES PLAN",
          "VEHICLE RANGE",
        ],
      },
    };

    const clientToUse = axiosInstance || axios;

    const response = await clientToUse.post(`https://na-mobile-api.gm.com/api/v1/account/vehicles/${vin}/commands/diagnostics`, postData, {
      headers: {
        Authorization: `Bearer ${gmapiTokenResponse.access_token}`,
        "Content-Type": "application/json; charset=UTF-8",
        Accept: "application/json",
      },
    });

    console.log("✅ Diagnostic request successful:", response.data);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`🚫 GM API Request Error ${error.response.status}`);
      console.error("🚫 Error details:", error.response.data || error.response.statusText);
      if (error.response.status === 401) {
        console.error("🚫 Authentication failed for API request. Token may be invalid or expired.");
      }
    } else if (error.request) {
      console.error("🚫 No response received from GM API for diagnostic request");
    } else {
      console.error("🚫 Request Error (diagnostics):", error.message);
    }
    throw error;
  }
}

// Call the main function
main().catch((error) => {
  console.error("🚫 Error in main execution:", error);
  exit(1);
});
