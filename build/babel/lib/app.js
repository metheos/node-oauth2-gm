"use strict";

var _dotenv = _interopRequireDefault(require("dotenv"));
var readline = _interopRequireWildcard(require("node:readline/promises"));
var _nodeProcess = require("node:process");
var _openidClient = _interopRequireWildcard(require("openid-client"));
var openidClient = _openidClient;
var _fs = _interopRequireDefault(require("fs"));
var _totpGenerator = require("totp-generator");
var _querystring = _interopRequireDefault(require("querystring"));
var _superagent = _interopRequireDefault(require("superagent"));
function _getRequireWildcardCache(e) { if ("function" != typeof WeakMap) return null; var r = new WeakMap(), t = new WeakMap(); return (_getRequireWildcardCache = function (e) { return e ? t : r; })(e); }
function _interopRequireWildcard(e, r) { if (!r && e && e.__esModule) return e; if (null === e || "object" != typeof e && "function" != typeof e) return { default: e }; var t = _getRequireWildcardCache(r); if (t && t.has(e)) return t.get(e); var n = { __proto__: null }, a = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var u in e) if ("default" !== u && {}.hasOwnProperty.call(e, u)) { var i = a ? Object.getOwnPropertyDescriptor(e, u) : null; i && (i.get || i.set) ? Object.defineProperty(n, u, i) : n[u] = e[u]; } return n.default = e, t && t.set(e, n), n; }
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
//SUPER-INIT
const tokenPath = "./microsoft_tokens.json"; // Path to the token storage file
const {
  Issuer,
  generators
} = openidClient;
var lastRedirect = null;
//set up GM token requestor
const agent = _superagent.default.agent();
var GMAPIToken = null;
var lastLoadedURL = "";
//set up browser
const rl = readline.createInterface({
  input: _nodeProcess.stdin,
  output: _nodeProcess.stdout
});
//set up variables
var user_email_addr = null;
var user_password = null;
var user_device_uuid = null;
var user_vehicle_vin = null;
var user_totp_key = null;

// Wrap the main logic in an async function
async function main() {
  //Variables
  _dotenv.default.config();
  user_email_addr = process.env.EMAIL ?? (await rl.question("Enter OnStar account email address:"));
  user_password = process.env.PASSWORD ?? (await rl.question("Enter OnStar account password:"));
  user_device_uuid = process.env.UUID ?? "";
  user_vehicle_vin = process.env.VIN ?? "";
  user_totp_key = process.env.TOTPKEY ?? "";

  // console.log(user_email_addr);

  if (user_email_addr == undefined) {
    console.log("Onstar Account Information must be provided.");
    (0, _nodeProcess.exit)();
  }

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
  (0, _nodeProcess.exit)();
}

// Call the main function
main().catch(error => {
  console.error("Error in main:", error);
  (0, _nodeProcess.exit)(1);
});
async function doFullAuthSequence() {
  const {
    authorizationUrl,
    code_verifier
  } = await startAuthorizationFlow();
  console.log("got PKCE code verifier:", code_verifier);

  //Follow authentication url
  console.log("Loading Auth URL");
  var authResponse = await getRequest(authorizationUrl);
  await getRequest("https://accounts.gm.com/common/login/index.html", false);
  var csrfToken = getRegexMatch(authResponse.text, `\"csrf\":\"(.*?)\"`);
  var transId = getRegexMatch(authResponse.text, `\"transId\":\"(.*?)\"`);
  console.log("Sending GM login credentials");
  const cpe1Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  // console.log(cpe1Url);
  const cpe1Data = {
    request_type: "RESPONSE",
    logonIdentifier: user_email_addr,
    password: user_password
  };
  var cpe1Response = await postRequest(cpe1Url, cpe1Data, csrfToken);

  //load the page that lets us request the MFA Code
  console.log("Loading MFA Page");
  const mfaRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=${csrfToken}&tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
  var authResponse = await getRequest(mfaRequestURL);
  var csrfToken = getRegexMatch(authResponse.text, `\"csrf\":\"(.*?)\"`);
  var transId = getRegexMatch(authResponse.text, `\"transId\":\"(.*?)\"`);
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
  console.log("Determined MFA Type is", mfaType);
  switch (mfaType) {
    case "SMS":
      throw new Error("SMS is not implemented! Sorry!");
      break;
    case "TOTP":
      //GENERATE AND SUBMIT TOTP CODE
      var mfaCode = "";
      if (user_totp_key && user_totp_key.trim() != "" && user_totp_key.length >= 16) {
        var totp_secret = user_totp_key;
        if (user_totp_key.includes("secret=")) {
          totp_secret = getRegexMatch(user_totp_key, "secret=(.*?)&");
        }
        const {
          otp,
          expires
        } = _totpGenerator.TOTP.generate(totp_secret, {
          digits: 6,
          algorithm: "SHA-1",
          period: 30
        });
        console.log("Generating and submitting OTP code:", otp);
        mfaCode = otp;
      } else {
        mfaCode = await rl.question("Enter MFA Code from Authenticator App:");
      }
      console.log("Submitting OTP Code:", mfaCode);
      var postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      var MFACodeDataResp = {
        otpCode: mfaCode,
        request_type: "RESPONSE"
      };
      var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);
      break;
    case "EMAIL":
      // REQUEST EMAIL MFA CODE
      console.log("Requesting MFA Code. Check your email!");
      const cpe2Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/SendCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      const cpe2Data = {
        emailMfa: user_email_addr
      };
      var cpe2Response = await postRequest(cpe2Url, cpe2Data, csrfToken);
      var mfaCode = await rl.question("Enter MFA Code from Email Message:");

      //submit MFA code
      console.log("Submitting MFA Code.");
      const postMFACodeURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl-RO/VerifyCode?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeURL);
      const MFACodeData = {
        emailMfa: user_email_addr,
        verificationCode: mfaCode
      };
      var MFACodeResponse = await postRequest(postMFACodeURL, MFACodeData, csrfToken);

      //RESPONSE - not sure what this does, but we need to do it to move on
      var postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
      // console.log(postMFACodeRespURL);
      var MFACodeDataResp = {
        emailMfa: user_email_addr,
        verificationCode: mfaCode,
        request_type: "RESPONSE"
      };
      var MFACodeResponse = await postRequest(postMFACodeRespURL, MFACodeDataResp, csrfToken);
      break;
    default:
      console.log("Could not determine MFA Type. Bad email or password?");
      (0, _nodeProcess.exit)();
      break;
  }
  if (mfaType != null) {
    //Get Auth Code in redirect (This actually contains the 'code' for completing PKCE in the oauth flow)
    const authCodeRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/SelfAsserted/confirmed?csrf_token=${csrfToken}&tx=${transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
    //Get auth Code request url
    var authResponse = await captureRedirectLocation(authCodeRequestURL);
    if (!authResponse.startsWith("msauth")) {
      throw new Error(`Did not obtain auth Code! page: ${authResponse}`);
    }
    const authCode = getRegexMatch(authResponse, `code=(.*)`);

    //use code with verifier to get MS access token!
    var thisTokenSet = await getAccessToken(authCode, code_verifier);

    //save the MS token set for reuse
    console.log("Saving MS tokens to ", tokenPath);
    _fs.default.writeFileSync(tokenPath, JSON.stringify(thisTokenSet));
  } else {
    console.log("Could not determine MFA Type");
    (0, _nodeProcess.exit)();
  }
  console.log("Complete");
}

//FUNCTIONS

async function getGMAPIToken(tokenSet) {
  console.log("Requesting GM API Token using MS Access Token");
  const url = "https://na-mobile-api.gm.com/sec/authz/v3/oauth/token";
  try {
    const response = await agent.post(url).type("form").send(_querystring.default.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: tokenSet.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      scope: "msso role_owner priv onstar gmoc user user_trailer",
      device_id: user_device_uuid
    })).withCredentials().set("Content-Type", "application/x-www-form-urlencoded").set("Accept", "application/json");
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
        diagnosticItem: ["TARGET CHARGE LEVEL SETTINGS", "LAST TRIP FUEL ECONOMY", "PREF CHARGING TIMES SETTING", "ENERGY EFFICIENCY", "LIFETIME ENERGY USED", "ESTIMATED CABIN TEMPERATURE", "EV BATTERY LEVEL", "HV BATTERY CHARGE COMPLETE TIME", "HIGH VOLTAGE BATTERY PRECONDITIONING STATUS", "EV PLUG VOLTAGE", "HOTSPOT CONFIG", "ODOMETER", "HOTSPOT STATUS", "LIFETIME EV ODOMETER", "CHARGER POWER LEVEL", "CABIN PRECONDITIONING TEMP CUSTOM SETTING", "EV PLUG STATE", "EV CHARGE STATE", "TIRE PRESSURE", "LOCATION BASE CHARGE SETTING", "LAST TRIP DISTANCE", "CABIN PRECONDITIONING REQUEST", "GET COMMUTE SCHEDULE", "GET CHARGE MODE", "PREF CHARGING TIMES PLAN", "VEHICLE RANGE"]
      }
    };
    const response = await agent.post(`https://na-mobile-api.gm.com/api/v1/account/vehicles/${user_vehicle_vin}/commands/diagnostics`).type("json").send(postData).withCredentials().set("authorization", `bearer ${GMAPIToken.access_token}`).set("content-type", "application/json; charset=UTF-8").set("Accept", "application/json");
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
    postData = _querystring.default.stringify(postData);
  } else {
    console.log(postData);
  }
  try {
    const response = await agent.post(url)
    // .proxy(proxyURL)
    .type("form").send(postData).withCredentials().set("Connection", "keep-alive").timeout(90000).set("Accept-Encoding", "gzip, deflate, br").set("Accept-Language", "en-US,en;q=0.9").set("Referer", lastLoadedURL).set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148").set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8").set("Accept", "application/json, text/javascript, */*; q=0.01").set("Origin", "https://custlogin.gm.com").set("X-Requested-With", "XMLHttpRequest").set("X-CSRF-TOKEN", csrfToken);
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
    const response = await agent.get(url)
    // .proxy(proxyURL)
    .withCredentials().accept("*/*").set("Referer", lastLoadedURL).set("origin", "https://custlogin.gm.com").set("Connection", "keep-alive").set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148");
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
    const response = await agent.get(url).redirects(0).ok(function (res) {
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
  const issuer = await Issuer.discover("https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/b2c_1a_seamless_mobile_signuporsignin/v2.0/.well-known/openid-configuration");

  // Initialize the client without client_secret since PKCE doesn't require it
  const client = new issuer.Client({
    client_id: "3ff30506-d242-4bed-835b-422bf992622e",
    redirect_uris: ["msauth.com.gm.myChevrolet://auth"],
    // Add your app's redirect URI here
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  });
  client[_openidClient.custom.clock_tolerance] = 60; // to allow a 60 second skew

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
    scope: "https://gmb2cprod.onmicrosoft.com/3ff30506-d242-4bed-835b-422bf992622e/Test.Read openid profile offline_access",
    // Add scopes as needed
    code_challenge,
    code_challenge_method: "S256"
  });

  // Return both the authorization URL and the code_verifier for later use
  return {
    authorizationUrl,
    code_verifier
  };
}

//complete PKCE and get the MS tokens
async function getAccessToken(code, code_verifier) {
  const client = await setupClient();
  try {
    // Exchange the authorization code and code verifier for an access token
    const tokenSet = await client.callback("msauth.com.gm.myChevrolet://auth", {
      code
    }, {
      code_verifier
    });
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
  if (_fs.default.existsSync(tokenPath)) {
    const storedTokens = JSON.parse(_fs.default.readFileSync(tokenPath));

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
  _fs.default.writeFileSync(tokenPath, JSON.stringify(tokenSet));
  return tokenSet;
}