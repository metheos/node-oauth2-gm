import dotenv from "dotenv";
import axios from "axios";
import { CookieJar } from "tough-cookie";
import { HttpCookieAgent, HttpsCookieAgent } from "http-cookie-agent/http";

import * as readline from "node:readline/promises";
import { exit, stdin as input, stdout as output } from "node:process";

import * as openidClient from "openid-client";

import fs from "fs";

import { TOTP } from "totp-generator";

//Variables
dotenv.config();
const user_email_addr = process.env.EMAIL;
const user_password = process.env.PASSWORD;
// const user_mfa_code = "";
const user_device_uuid = process.env.UUID;
const user_vehicle_vin = process.env.VIN;
const user_totp_key = process.env.TOTPKEY;

console.log(user_email_addr);

if (user_email_addr == undefined) {
  console.log("copy .env.example to .env and enter your account information");
  exit();
}

//INIT
const tokenPath = "./tokens.json"; // Path to the token storage file

const rl = readline.createInterface({ input, output });

const { Issuer, generators } = openidClient;

const jar = new CookieJar();

const axiosClient = axios.create({
  httpAgent: new HttpCookieAgent({ cookies: { jar } }),
  httpsAgent: new HttpsCookieAgent({ cookies: { jar } }),
});

//Do the things!!
var GMAPIToken = null;

//Try to load a saved token set
var loadedTokenSet = await loadAccessToken();
if (loadedTokenSet !== false) {
  //we already have our MS tokens, let's use them to get the access token for the GM API!
  // console.log(loadedTokenSet);
  console.log("Existing tokens loaded!");
} else {
  console.log("No existing tokens found or were invalid. Doing full auth sequence.");
  try {
    await doFullAuthSequence();
  } catch (error) {
    console.error("Authentication sequence failed:", error.message);
    process.exit(1);
  }
  loadedTokenSet = await loadAccessToken();
}
//use the GM API token to make an API request
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

async function doFullAuthSequence() {
  const { authorizationUrl, code_verifier } = await startAuthorizationFlow();

  // Store `code_verifier` securely until you need it for the token request
  // console.log("Navigate to this URL to authenticate:", authorizationUrl);

  // You can save `code_verifier` in a session or pass it to the next stage
  console.log("got PKCE code verifier:", code_verifier);

  //Follow authentication url
  var authResponse = await getRequest(authorizationUrl);

  //get correlation id
  // var CorrelationId = getRegexMatch(authResponse.data, "CorrelationId: (.*?) -->");
  //get csrf
  var csrfToken = getRegexMatch(authResponse.data, `\"csrf\":\"(.*?)\"`);
  //get transId/stateproperties
  var transId = getRegexMatch(authResponse.data, `\"transId\":\"(.*?)\"`);

  //send credentials to custom policy endpoint
  console.log("Sending GM login credentials");
  const cpe1Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // console.log(cpe1Url);
  const cpe1Data = {
    request_type: "RESPONSE",
    logonIdentifier: user_email_addr,
    password: user_password,
  };
  var cpe1Response = await postRequest(cpe1Url, cpe1Data, csrfToken);

  //load the page that lets us request the MFA Code
  console.log("Loading MFA Page");
  const mfaRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=${csrfToken}&tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  //Get MFA request url
  var authResponse = await getRequest(mfaRequestURL);
  //get csrf
  var csrfToken = getRegexMatch(authResponse.data, `\"csrf\":\"(.*?)\"`);
  //get transId/stateproperties
  var transId = getRegexMatch(authResponse.data, `\"transId\":\"(.*?)\"`);

  //GENERATE AND SUBMIT TOTP CODE
  const { otp, expires } = TOTP.generate(user_totp_key, {
    digits: 6,
    algorithm: "SHA-1",
    period: 30,
  });
  console.log("Submitting OTP Code:", otp);
  const postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // console.log(postMFACodeRespURL);
  const MFACodeDataResp = {
    otpCode: otp,
    request_type: "RESPONSE",
  };
  var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);

  // // request mfa code
  // console.log("Requesting MFA Code. Check your email!");
  // const cpe2Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/SendCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // // console.log(cpe2Url);
  // const cpe2Data = {
  //   emailMfa: user_email_addr,
  // };
  // var cpe2Response = await postRequest(cpe2Url, cpe2Data, csrfToken);
  // var mfaCode = await rl.question("MFA Code from email:");
  // // var mfaCode = user_mfa_code;

  // //submit MFA code
  // console.log("Submitting MFA Code.");
  // const postMFACodeURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/VerifyCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // // console.log(postMFACodeURL);
  // const MFACodeData = {
  //   emailMfa: user_email_addr,
  //   verificationCode: mfaCode,
  // };
  // var MFACodeResponse = await postRequest(postMFACodeURL, MFACodeData, csrfToken);

  // //RESPONSE - not sure what this does, but we need to do it to move on
  // const postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // // console.log(postMFACodeRespURL);
  // const MFACodeDataResp = {
  //   emailMfa: user_email_addr,
  //   verificationCode: mfaCode,
  //   request_type: "RESPONSE",
  // };
  // var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);

  //Get Auth Code in redirect (This actually contains the 'code' for completing PKCE in the oauth flow)
  const authCodeRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/SelfAsserted/confirmed?csrf_token=${csrfToken}&tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  //Get auth Code request url
  var authResponse = await captureRedirectLocation(authCodeRequestURL);
  // console.log(authResponse);
  //get 'code'
  var authCode = getRegexMatch(authResponse, `code=(.*)`);
  // console.log("Auth Code:", authCode);

  //use code with verifier to get MS access token!
  var thisTokenSet = await getAccessToken(authCode, code_verifier);
  // console.log(thisTokenSet);

  //save the MS token set for reuse
  console.log("Saving MS tokens to ", tokenPath);
  fs.writeFileSync(tokenPath, JSON.stringify(thisTokenSet));
}

//FUNCTIONS
async function getGMAPIToken(tokenSet) {
  console.log("Requesting GM API Token using MS Access Token");
  const url = "https://na-mobile-api.gm.com/sec/authz/v3/oauth/token";

  try {
    const response = await axiosClient.post(
      url,
      {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: tokenSet.access_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        scope: "msso role_owner priv onstar gmoc user user_trailer",
        device_id: user_device_uuid,
      },
      {
        withCredentials: true,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
      }
    );

    const expires_at = Math.floor(new Date() / 1000) + parseInt(response.data.expires_in);
    response.data.expires_at = expires_at;
    console.log("Set GM Token expiration to ", expires_at);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`GM API Token Error ${error.response.status}: ${error.response.statusText}`);
      console.error("Error details:", error.response.data);
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
    if (GMAPIToken.expires_at < now) {
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

    const response = await axiosClient.post(
      `https://na-mobile-api.gm.com/api/v1/account/vehicles/${user_vehicle_vin}/commands/diagnostics`,
      postData,
      {
        withCredentials: true,
        headers: {
          authorization: `bearer ${GMAPIToken.access_token}`,
          "content-type": "application/json; charset=UTF-8",
          accept: "application/json",
        },
      }
    );

    console.log("Diagnostic request successful:", response.data);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`GM API Request Error ${error.response.status}: ${error.response.statusText}`);
      console.error("Error details:", error.response.data);
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

//post request function for the MS oauth side of things
async function postRequest(url, postData, csrfToken = "") {
  try {
    const response = await axiosClient.post(url, postData, {
      withCredentials: true,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        accept: "application/json, text/javascript, */*; q=0.01",
        origin: "https://custlogin.gm.com",
        "x-csrf-token": csrfToken,
      },
    });
    console.log("Response Status:", response.status);
    return response;
  } catch (error) {
    if (error.response) {
      console.error(`HTTP Error ${error.response.status}: ${error.response.statusText}`);
      console.error("Response data:", error.response.data);
      if (error.response.status === 401) {
        console.error("Authentication failed. Please check your credentials.");
      }
    } else if (error.request) {
      console.error("No response received from server");
      console.error(error.request);
    } else {
      console.error("Request Error:", error.message);
    }
    throw error;
  }
}

//general get request function with cookie support
async function getRequest(url) {
  try {
    const response = await axiosClient.get(url, { withCredentials: true, maxRedirects: 0 });
    console.log("Response Status:", response.status);
    return response;
  } catch (error) {
    if (error.response) {
      // Server responded with error status
      console.error(`HTTP Error ${error.response.status}: ${error.response.statusText}`);
      console.error("Response data:", error.response.data);
    } else if (error.request) {
      // Request made but no response received
      console.error("No response received from server");
      console.error(error.request);
    } else {
      // Error in request setup
      console.error("Request Error:", error.message);
    }
    throw error;
  }
}

//this helps grab the MS oauth pkce code response
async function captureRedirectLocation(url) {
  console.log("Requesting PKCE code");
  try {
    const response = await axiosClient.get(url, {
      maxRedirects: 0,
      validateStatus: function (status) {
        return status >= 200 && status < 400;
      },
    });

    if (response.status === 302) {
      const redirectLocation = response.headers["location"];
      if (!redirectLocation) {
        throw new Error("No redirect location found in response headers");
      }
      return redirectLocation;
    } else {
      console.log("Unexpected response status:", response.status);
      return false;
    }
  } catch (error) {
    if (error.response) {
      console.error(`Redirect Error ${error.response.status}: ${error.response.statusText}`);
      console.error("Response data:", error.response.data);
    } else if (error.request) {
      console.error("No response received while capturing redirect");
      console.error(error.request);
    } else {
      console.error("Request Error:", error.message);
    }
    throw error;
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
    if (storedTokens.expires_at > now) {
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
