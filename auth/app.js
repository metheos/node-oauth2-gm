import dotenv from "dotenv";
import * as readline from "node:readline/promises";
import { exit, stdin as input, stdout as output } from "node:process";
import * as openidClient from "openid-client";
import fs from "fs";
import { TOTP } from "totp-generator";
import querystring from "querystring";
import puppeteer, { Browser, KnownDevices } from "puppeteer";
import superagent from "superagent";

//SUPER-INIT
const tokenPath = "./microsoft_tokens.json"; // Path to the token storage file
const { Issuer, generators } = openidClient;
var lastRedirect = null;
//set up GM token requestor
const agent = superagent.agent();
var GMAPIToken = null;
//set up browser
const iPhone = KnownDevices["iPhone 15 Pro Max"];
const rl = readline.createInterface({ input, output });
//set up variables
var user_email_addr = null;
var user_password = null;
var user_device_uuid = null;
var user_vehicle_vin = null;
var user_totp_key = null;

// Wrap the main logic in an async function
async function main() {
  //Variables
  dotenv.config();
  user_email_addr = process.env.EMAIL ?? (await rl.question("Enter OnStar account email address:"));
  user_password = process.env.PASSWORD ?? (await rl.question("Enter OnStar account password:"));
  user_device_uuid = process.env.UUID ?? "";
  user_vehicle_vin = process.env.VIN ?? "";
  user_totp_key = process.env.TOTPKEY ?? "";

  // console.log(user_email_addr);

  if (user_email_addr == undefined) {
    console.log("Onstar Account Information must be provided.");
    exit();
  }

  //INIT
  // const browser = await puppeteer.launch({ devtools: true });
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.emulate(iPhone);

  // capture background responses
  page.on("response", async (response) => {
    // Check if the response is a redirect (3xx status code)
    if (response.status() >= 300 && response.status() < 400) {
      // Optionally, you can log the redirect URL or handle it as needed
      const thisRedirect = response.headers()["location"];
      if (thisRedirect.includes("msauth")) {
        lastRedirect = thisRedirect;
      }
      // console.log(`Redirect detected: ${lastRedirect}`);
      return; // Exit the function early to avoid further processing
    }
    if (response.url().includes("SendCode")) {
      const content = await response.text();

      if (content.includes("errorCode")) {
        throw new Error(`Failed to send SMS Code. See error details for more information: ${content}`);
      }
    }
  });

  //Try to load a saved token set
  var loadedTokenSet = await loadAccessToken();
  if (loadedTokenSet !== false) {
    //we already have our MS tokens, let's use them to get the access token for the GM API!
    // console.log(loadedTokenSet);
    console.log("Existing tokens loaded!");
  } else {
    console.log("No existing tokens found or were invalid. Doing full auth sequence.");
    try {
      await doFullAuthSequence(page);
    } catch (error) {
      console.error("Authentication sequence failed:", error.message);
      process.exit(1);
    }
    loadedTokenSet = await loadAccessToken();
  }
  if (user_device_uuid != "" && user_vehicle_vin != "") {
    // Get a GM API token and use it to make an API request
    try {
      GMAPIToken = await getGMAPIToken(loadedTokenSet);
    } catch (error) {
      console.error("Authentication sequence failed:", error.message);
      process.exit(1);
    }
    console.log(GMAPIToken);
    try {
      await testGMAPIRequest(GMAPIToken);
    } catch (error) {
      console.error("API Test failed:", error.message);
      process.exit(1);
    }
  }
  exit();
}

// Call the main function
main().catch((error) => {
  console.error("Error in main:", error);
  exit(1);
});

async function doFullAuthSequence(page) {
  const { authorizationUrl, code_verifier } = await startAuthorizationFlow();
  console.log("got PKCE code verifier:", code_verifier);

  //Follow authentication url
  console.log("Loading Auth URL");
  await page.goto(authorizationUrl);
  await page.waitForNetworkIdle({ idleTime: 3000 });

  console.log("Submitting user email and password");
  await page.locator("#logonIdentifier").fill(user_email_addr);
  await page.locator("#password").fill(user_password);
  await page.locator("#next").click();

  await page.waitForNetworkIdle({ idleTime: 500 });

  //HANDLE MFA
  var mfaType = null;
  var pageContent = await page.content();

  if (pageContent.includes("otpCode")) {
    mfaType = "TOTP";
  }
  if (pageContent.includes("emailMfa")) {
    mfaType = "EMAIL";
  }
  if (pageContent.includes("strongAuthenticationPhoneNumber")) {
    mfaType = "SMS";
  }
  console.log("Determined MFA Type is", mfaType);
  switch (mfaType) {
    case "SMS":
      var mfaCode = await rl.question("Enter MFA Code from SMS Message:");
      await page.locator("#verificationCode").fill(mfaCode);
      await page.locator("button.verifyCode").click();
      break;

    case "TOTP":
      //GENERATE AND SUBMIT TOTP CODE
      var mfaCode = "";
      if (user_totp_key && user_totp_key.trim() != "" && user_totp_key.length >= 16) {
        var totp_secret = user_totp_key;
        if (user_totp_key.includes("secret=")) {
          totp_secret = getRegexMatch(user_totp_key, "secret=(.*?)&");
        }
        const { otp, expires } = TOTP.generate(totp_secret, {
          digits: 6,
          algorithm: "SHA-1",
          period: 30,
        });
        console.log("Generating and submitting OTP code:", otp);
        mfaCode = otp;
      } else {
        mfaCode = await rl.question("Enter MFA Code from Authenticator App:");
      }
      await page.locator("#otpCode").fill(mfaCode);
      await page.locator("#continue").click();
      break;

    case "EMAIL":
      var mfaCode = await rl.question("Enter MFA Code from Email Message:");
      await page.locator("#verificationCode").fill(mfaCode);
      await page.locator("button.verifyCode").click();
      break;

    default:
      console.log("Could not determine MFA Type");
      exit();
      break;
  }

  if (mfaType != null) {
    //Get Auth Code in redirect (This actually contains the 'code' for completing PKCE in the oauth flow)
    console.log("Waiting for auth redirect");
    const redirectUrl = await waitForRedirect();
    if (!redirectUrl.startsWith("msauth")) {
      throw new Error(`Did not obtain auth Code! page: ${redirectUrl}`);
    }

    const authCode = getRegexMatch(redirectUrl, `code=(.*)`);

    //use code with verifier to get MS access token!
    var thisTokenSet = await getAccessToken(authCode, code_verifier);
    // console.log(thisTokenSet);

    //save the MS token set for reuse
    console.log("Saving MS tokens to ", tokenPath);
    fs.writeFileSync(tokenPath, JSON.stringify(thisTokenSet));
  } else {
    console.log("Could not determine MFA Type");
    exit();
  }
  console.log("Complete");
}

//FUNCTIONS

// Function to wait for lastRedirect to be set
async function waitForRedirect(timeout = 10000) {
  // Default timeout of 10 seconds
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const checkRedirect = setInterval(() => {
      if (lastRedirect) {
        clearInterval(checkRedirect);
        resolve(lastRedirect);
      } else if (Date.now() - startTime > timeout) {
        clearInterval(checkRedirect);
        reject(new Error("Timeout waiting for auth code redirect"));
      }
    }, 100); // Check every 100 milliseconds
  });
}

async function getGMAPIToken(tokenSet) {
  console.log("Requesting GM API Token using MS Access Token");
  const url = "https://na-mobile-api.gm.com/sec/authz/v3/oauth/token";

  try {
    const response = await agent
      .post(url)
      .type("form")
      .send(
        querystring.stringify({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: tokenSet.access_token,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
          scope: "msso role_owner priv onstar gmoc user user_trailer",
          device_id: user_device_uuid,
        })
      )
      .withCredentials()
      .set("Content-Type", "application/x-www-form-urlencoded")
      .set("Accept", "application/json");

    const expires_at = Math.floor(new Date() / 1000) + parseInt(response.body.expires_in);
    response.body.expires_at = expires_at;
    console.log("Set GM Token expiration to ", expires_at);
    return response.body;
  } catch (error) {
    if (error.response) {
      console.error(`GM API Token Error ${error.response.status}`);
      console.error("Error details:", error.response.body);
      if (error.response.status === 401) {
        console.error("Token exchange failed. MS Access token may be invalid.");
      }
    } else if (error.request) {
      console.error("No response received from GM API");
      console.error(error.request);
    } else {
      console.error("Request Error:", error.message);
    }
    throw error;
  }
}
//Test the GMA API using the GM API token
async function testGMAPIRequest(GMAPIToken) {
  console.log("Testing GM API Request");
  try {
    const now = Math.floor(Date.now() / 1000);
    if (GMAPIToken.expires_at < now + 5 * 60) {
      console.log("Token expired, refreshing...");
      GMAPIToken = await getGMAPIToken(loadedTokenSet);
    }

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

    const response = await agent
      .post(`https://na-mobile-api.gm.com/api/v1/account/vehicles/${user_vehicle_vin}/commands/diagnostics`)
      .type("json")
      .send(postData)
      .withCredentials()
      .set("authorization", `bearer ${GMAPIToken.access_token}`)
      .set("content-type", "application/json; charset=UTF-8")
      .set("Accept", "application/json");

    console.log("Diagnostic request successful:", response.body);
    return response.body;
  } catch (error) {
    if (error.response) {
      console.error(`GM API Request Error ${error.response.status}`);
      console.error("Error details:", error.response.body);
      if (error.response.status === 401) {
        console.error("Authentication failed. Token may be invalid.");
      }
    } else if (error.request) {
      console.error("No response received from GM API");
      console.error(error.request);
    } else {
      console.error("Request Error:", error.message);
    }
    throw error;
  }
}

//little function to make grabbing a regex match simple
function getRegexMatch(haystack, regexString) {
  let re = new RegExp(regexString);
  let r = haystack.match(re);
  if (r) {
    // console.log(r[1]);
    return r[1];
  } else {
    return false;
  }
}

// Discover the issuer
async function setupClient() {
  console.log("Doing auth discovery");
  const issuer = await Issuer.discover(
    "https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/.well-known/openid-configuration"
  );

  // Initialize the client without client_secret since PKCE doesn't require it
  const client = new issuer.Client({
    client_id: "3ff30506-d242-4bed-835b-422bf992622e",
    redirect_uris: ["msauth.com.gm.myChevrolet://auth"], // Add your app's redirect URI here
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  });

  return client;
}

//starts PKCE auth
async function startAuthorizationFlow() {
  console.log("Starting PKCE auth");
  const client = await setupClient();

  // Generate the code verifier and code challenge for PKCE
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  // Generate the authorization URL with the code challenge for PKCE
  const authorizationUrl = client.authorizationUrl({
    // scope:                    https://gmb2cprod.onmicrosoft.com/3ff30506-d242-4bed-835b-422bf992622e/Test.Read openid profile offline_access
    scope: "https://gmb2cprod.onmicrosoft.com/3ff30506-d242-4bed-835b-422bf992622e/Test.Read openid profile offline_access", // Add scopes as needed
    code_challenge,
    code_challenge_method: "S256",
  });

  // Return both the authorization URL and the code_verifier for later use
  return { authorizationUrl, code_verifier };
}

//complete PKCE and get the MS tokens
async function getAccessToken(code, code_verifier) {
  const client = await setupClient();

  try {
    // Exchange the authorization code and code verifier for an access token
    const tokenSet = await client.callback("msauth.com.gm.myChevrolet://auth", { code }, { code_verifier });

    console.log("Access Token:", tokenSet.access_token);
    console.log("ID Token:", tokenSet.id_token);

    return tokenSet;
  } catch (err) {
    console.error("Failed to obtain access token:", err);
    throw err;
  }
}

//load any existing tokens and renew them if expired and renewable
async function loadAccessToken() {
  console.log("Loading existing MS tokens, if they exist.");
  const client = await setupClient();
  var tokenSet;
  // Load existing tokens
  if (fs.existsSync(tokenPath)) {
    const storedTokens = JSON.parse(fs.readFileSync(tokenPath));

    // Check if access token is expired and refresh if necessary
    const now = Math.floor(Date.now() / 1000);
    if (storedTokens.expires_at > now + 5 * 60) {
      // Access token is still valid
      console.log("MS Access token is still valid");
      tokenSet = storedTokens;
    } else if (storedTokens.refresh_token) {
      // Access token expired, refresh with the refresh token
      console.log("Refreshing MS access token");
      tokenSet = await client.refresh(storedTokens.refresh_token);
    } else {
      // No valid tokens; re-authentication needed
      throw new Error("Token expired and no refresh token available.");
      return false;
    }
  } else {
    // No token found; authentication needed
    return false;
  }

  // Save the updated tokens after any refresh
  console.log("Saving current MS tokens to ", tokenPath);
  fs.writeFileSync(tokenPath, JSON.stringify(tokenSet));

  return tokenSet;
}
