import dotenv from "dotenv";

import * as readline from "node:readline/promises";
import { exit, stdin as input, stdout as output } from "node:process";

import * as openidClient from "openid-client";

import fs from "fs";

import { TOTP } from "totp-generator";

import superagent from "superagent";
// import superagentProxy from "superagent-proxy";
import querystring from "querystring";

//Variables
dotenv.config();
const user_email_addr = process.env.EMAIL;
const user_password = process.env.PASSWORD;
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

//PROXY SUPPORT
// const proxyURL = "http://127.0.0.1:8000";
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// superagentProxy(superagent);

const agent = superagent.agent();

//Do the things!!
var GMAPIToken = null;
var lastLoadedURL = "";

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
exit();

async function doFullAuthSequence() {
  const { authorizationUrl, code_verifier } = await startAuthorizationFlow();

  // Store `code_verifier` securely until you need it for the token request
  // console.log("Navigate to this URL to authenticate:", authorizationUrl);

  // You can save `code_verifier` in a session or pass it to the next stage
  console.log("got PKCE code verifier:", code_verifier);

  //Follow authentication url
  console.log("Loading Auth URL");
  var authResponse = await getRequest(authorizationUrl);

  await getRequest("https://accounts.gm.com/common/login/index.html", false);

  //get correlation id
  // var CorrelationId = getRegexMatch(authResponse.body, "CorrelationId: (.*?) -->");
  //get csrf
  var csrfToken = getRegexMatch(authResponse.text, `\"csrf\":\"(.*?)\"`);
  //get transId/stateproperties
  var transId = getRegexMatch(authResponse.text, `\"transId\":\"(.*?)\"`);

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
  var csrfToken = getRegexMatch(authResponse.text, `\"csrf\":\"(.*?)\"`);
  //get transId/stateproperties
  var transId = getRegexMatch(authResponse.text, `\"transId\":\"(.*?)\"`);
  // console.log(authResponse.body);

  var mfaType = null;
  if (authResponse.text.includes("otpCode")) {
    mfaType = "TOTP";
  }
  if (authResponse.text.includes("emailMfa")) {
    mfaType = "EMAIL";
  }
  if (authResponse.text.includes("strongAuthenticationPhoneNumber")) {
    mfaType = "SMS";
  }
  console.log("MFA Type:", mfaType);

  switch (mfaType) {
    case "TOTP":
      //GENERATE AND SUBMIT TOTP CODE
      const { otp, expires } = TOTP.generate(user_totp_key, {
        digits: 6,
        algorithm: "SHA-1",
        period: 30,
      });
      console.log("Submitting OTP Code:", otp);
      var postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      var MFACodeDataResp = {
        otpCode: otp,
        request_type: "RESPONSE",
      };
      var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);

      break;

    case "EMAIL":
      // REQUEST EMAIL MFA CODE
      console.log("Requesting MFA Code. Check your email!");
      const cpe2Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/SendCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(cpe2Url);
      const cpe2Data = {
        emailMfa: user_email_addr,
      };
      var cpe2Response = await postRequest(cpe2Url, cpe2Data, csrfToken);
      var mfaCode = await rl.question("MFA Code from email:");
      // var mfaCode = user_mfa_code;

      //submit MFA code
      console.log("Submitting MFA Code.");
      const postMFACodeURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/VerifyCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeURL);
      const MFACodeData = {
        emailMfa: user_email_addr,
        verificationCode: mfaCode,
      };
      var MFACodeResponse = await postRequest(postMFACodeURL, MFACodeData, csrfToken);

      //RESPONSE - not sure what this does, but we need to do it to move on
      var postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeRespURL);
      var MFACodeDataResp = {
        emailMfa: user_email_addr,
        verificationCode: mfaCode,
        request_type: "RESPONSE",
      };
      var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);

      break;

    case "SMS":
      const SMS_PRE = getRegexMatch(authResponse.text, '"PRE": *"(.*?)"');

      //load MFA
      // var mfaJunk = null;
      // mfaJunk = await getRequest(`https://accounts.gm.com/mfa/ui/`);
      // mfaJunk = await getRequest(`https://accounts.gm.com/mfa/ui/config`);
      // mfaJunk = await getRequest(`https://accounts.gm.com/mfa/cms/en-US/translations`);
      // mfaJunk = await getRequest(`https://accounts.gm.com/mfa/assets/styles/v2-gbds-override.css`);

      // SEND SMS MFA CODE

      console.log("Requesting MFA Code. Check your messages!");
      const smsSendUrl = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/phoneVerificationControl-readOnly/SendCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(cpe2Url);
      // const smsSendData = `&strongAuthenticationPhoneNumber=${SMS_PRE}`;
      const smsSendData = `&strongAuthenticationPhoneNumber=XXXX-XXX-7637`;
      var smsSendResponse = await postRequest(smsSendUrl, smsSendData, csrfToken, true);
      console.log(smsSendResponse.text);
      if (smsSendResponse.text.message.includes(`HTTP error response with Code '429'`)) {
        console.log("SMS Request Rate Limit Exceeded. Please try again later.");
        exit();
      }
      var mfaCode = await rl.question("MFA Code from SMS:");

      //submit MFA code
      console.log("Submitting MFA Code.");
      const postSMSMFACodeURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/phoneVerificationControl-readOnly/VerifyCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeURL);
      const SMSMFACodeData = `&strongAuthenticationPhoneNumber=SMS_PRE&verificationCode=mfaCode`;
      var MFACodeResponse = await postRequest(postSMSMFACodeURL, SMSMFACodeData, csrfToken);
      console.log(MFACodeResponse.text);

      //RESPONSE - not sure what this does, but we need to do it to move on
      var postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeRespURL);
      var MFACodeDataResp = {
        strongAuthenticationPhoneNumber: SMS_PRE,
        verificationCode: mfaCode,
        request_type: "RESPONSE",
      };
      var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);
      console.log(MFACodeResponse.text);
      break;

    default:
      console.log("Could not determine MFA Type");
      exit();
      break;
  }

  if (mfaType != null) {
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
  } else {
    console.log("Could not determine MFA Type");
    exit();
  }
  console.log("Complete");
}

//FUNCTIONS
async function getGMAPIToken(tokenSet) {
  console.log("Requesting GM API Token using MS Access Token");
  const url = "https://na-mobile-api.gm.com/sec/authz/v3/oauth/token";

  try {
    const response = await agent
      .post(url)
      // .proxy(proxyURL)
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

    const response = await agent
      .post(`https://na-mobile-api.gm.com/api/v1/account/vehicles/${user_vehicle_vin}/commands/diagnostics`)
      // .proxy(proxyURL)
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

//post request function for the MS oauth side of things
async function postRequest(url, postData, csrfToken = "", preserialized = false) {
  if (!preserialized) {
    postData = querystring.stringify(postData);
  } else {
    console.log(postData);
  }
  try {
    const response = await agent
      .post(url)
      // .proxy(proxyURL)
      .type("form")
      .send(postData)
      .withCredentials()
      .set("Connection", "keep-alive")
      .timeout(90000)
      .set("Accept-Encoding", "gzip, deflate, br")
      .set("Accept-Language", "en-US,en;q=0.9")
      .set("Referer", lastLoadedURL)
      .set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148")
      .set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
      .set("Accept", "application/json, text/javascript, */*; q=0.01")
      .set("Origin", "https://custlogin.gm.com")
      .set("X-Requested-With", "XMLHttpRequest")
      .set("X-CSRF-TOKEN", csrfToken);
    lastLoadedURL = url;
    return response;
  } catch (error) {
    if (error.response) {
      console.error(`HTTP Error ${error.response.status}`);
      console.error("Response data:", error.response.body);
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
async function getRequest(url, setRefer = true) {
  try {
    const response = await agent
      .get(url)
      // .proxy(proxyURL)
      .withCredentials()
      .accept("*/*")
      .set("Referer", lastLoadedURL)
      .set("origin", "https://custlogin.gm.com")
      .set("Connection", "keep-alive")
      .set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148");
    if (setRefer) lastLoadedURL = url;

    console.log("Response Status:", response.status);
    return response;
  } catch (error) {
    if (error.response) {
      // Server responded with error status
      console.error(`HTTP Error ${error.response.status}`);
      console.error("Response data:", error.response.body);
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
    const response = await agent
      .get(url)
      .redirects(0)
      .ok(function (res) {
        if (res.status == 302) {
          return true;
        } else throw new Error(res.body.message);
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
      console.error(`Redirect Error ${error.response.status}`);
      console.error("Response data:", error.response.text);
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
