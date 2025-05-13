import dotenv from "dotenv";
import * as readline from "node:readline/promises";
import { exit, stdin as input, stdout as output } from "node:process";
import fs from "fs";
import path from "path";
import axios from "axios";
import { CookieJar } from "tough-cookie";
import { HttpCookieAgent, HttpsCookieAgent } from "http-cookie-agent/http";
import jwt from "jsonwebtoken";
import { TOTP } from "totp-generator";
import https from "https";
import { custom } from "openid-client";
import * as openidClient from "openid-client";

// Set up readline interface
const rl = readline.createInterface({ input, output });

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
    this.debugMode = false;

    this.loadCurrentGMAPIToken();
  }

  async authenticate() {
    try {
      let loadedTokenSet = await this.loadMSToken();
      if (loadedTokenSet !== false) {
        if (this.debugMode) console.log("Using existing MS tokens");
        return await this.getGMAPIToken(loadedTokenSet);
      }

      if (this.debugMode) console.log("Performing full authentication");
      await this.doFullAuthSequence();
      loadedTokenSet = await this.loadMSToken();
      if (!loadedTokenSet) {
        throw new Error("Failed to load MS token set and could not generate a new one");
      }
      return await this.getGMAPIToken(loadedTokenSet);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.handleRequestError(error);
      } else {
        console.error("Authentication failed:", error);
      }
      throw error;
    }
  }

  async doFullAuthSequence() {
    const { authorizationUrl, code_verifier } = await this.startMSAuthorizationFlow();
    const authResponse = await this.getRequest(authorizationUrl);
    this.csrfToken = this.getRegexMatch(authResponse.data, `\\"csrf\\":\\"(.*?)\\"`);
    this.transId = this.getRegexMatch(authResponse.data, `\\"transId\\":\\"(.*?)\\"`);

    if (!this.csrfToken || !this.transId) {
      throw new Error("Failed to extract csrf token or transId");
    }

    await this.submitCredentials();
    await this.handleMFA();
    const authCode = await this.getAuthorizationCode();
    if (!authCode) {
      throw new Error("Failed to get authorization code. Bad TOTP Key?");
    }

    const tokenSet = await this.getMSToken(authCode, code_verifier);
    await this.saveTokens(tokenSet);
    return tokenSet;
  }

  async saveTokens(tokenSet) {
    if (this.debugMode) console.log("Saving MS tokens to ", this.MSTokenPath);
    fs.writeFileSync(this.MSTokenPath, JSON.stringify(tokenSet));

    if (this.currentGMAPIToken) {
      if (this.debugMode) console.log("Saving GM tokens to ", this.GMTokenPath);
      fs.writeFileSync(this.GMTokenPath, JSON.stringify(this.currentGMAPIToken));
    }
  }

  async getAuthorizationCode() {
    const authCodeRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/SelfAsserted/confirmed?csrf_token=${this.csrfToken}&tx=${this.transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
    const authResponse = await this.captureRedirectLocation(authCodeRequestURL);
    return this.getRegexMatch(authResponse, `code=(.*)`);
  }

  async handleMFA() {
    if (this.debugMode) console.log("Loading MFA Page");
    const mfaRequestURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=${this.csrfToken}&tx=${this.transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;

    const authResponse = await this.getRequest(mfaRequestURL);
    this.csrfToken = this.getRegexMatch(authResponse.data, `\\"csrf\\":\\"(.*?)\\"`);
    this.transId = this.getRegexMatch(authResponse.data, `\\"transId\\":\\"(.*?)\\"`);

    if (!this.csrfToken || !this.transId) {
      throw new Error("Failed to extract csrf token or transId during MFA");
    }

    var mfaType = null;
    if (authResponse.data.includes("otpCode")) mfaType = "TOTP";
    if (authResponse.data.includes("emailMfa")) mfaType = "EMAIL";
    if (authResponse.data.includes("strongAuthenticationPhoneNumber")) mfaType = "SMS";

    if (this.debugMode) console.log("Determined MFA Type is", mfaType);

    if (mfaType == null) {
      throw new Error("Could not determine MFA Type. Bad email or password?");
    }
    if (mfaType !== "TOTP") {
      throw new Error(`Only TOTP via "Third-Party Authenticator" is currently supported. Please update your OnStar account.`);
    }

    var totp_secret = this.config.totpKey.trim();
    if (totp_secret.includes("secret=")) {
      const match = this.getRegexMatch(totp_secret, "secret=(.*?)&");
      totp_secret = match ?? totp_secret;
    }

    const { otp } = TOTP.generate(totp_secret, { digits: 6, algorithm: "SHA-1", period: 30 });
    if (this.debugMode) console.log("Submitting OTP Code:", otp);
    const postMFACodeRespURL = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${this.transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
    const MFACodeDataResp = { otpCode: otp, request_type: "RESPONSE" };
    await this.postRequest(postMFACodeRespURL, MFACodeDataResp, this.csrfToken);
  }

  async submitCredentials() {
    if (this.debugMode) console.log("Sending GM login credentials");
    const cpe1Url = `https://custlogin.gm.com/gmb2cprod.onmicrosoft.com/B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn/SelfAsserted?tx=${this.transId}&p=B2C_1A_SEAMLESS_MOBILE_SignUpOrSignIn`;
    const cpe1Data = {
      request_type: "RESPONSE",
      logonIdentifier: this.config.username,
      password: this.config.password,
    };
    await this.postRequest(cpe1Url, cpe1Data, this.csrfToken);
  }

  static GMAuthTokenIsValid(authToken) {
    return authToken && authToken.expires_at && authToken.expires_at > Date.now() / 1000 + 5 * 60;
  }

  async loadCurrentGMAPIToken() {
    if (this.debugMode) console.log("Loading existing GM API token, if it exists.");
    if (fs.existsSync(this.GMTokenPath)) {
      try {
        const storedToken = JSON.parse(fs.readFileSync(this.GMTokenPath, "utf-8"));
        const decodedPayload = jwt.decode(storedToken.access_token);

        if (!decodedPayload || decodedPayload?.uid?.toUpperCase() !== this.config.username.toUpperCase()) {
          if (this.debugMode) console.log("Stored GM API token was for different user, getting new token");
        } else {
          const now = Math.floor(Date.now() / 1000);
          if (storedToken.expires_at && storedToken.expires_at > now + 5 * 60) {
            if (this.debugMode) console.log("Loaded existing GM API token");
            this.currentGMAPIToken = storedToken;
          } else {
            if (this.debugMode) console.log("Existing GM API token has expired");
          }
        }
      } catch (err) {
        console.warn("Stored GM API token was not parseable or invalid, getting new token:", err.message);
      }
    } else {
      if (this.debugMode) console.log("No existing GM API token file found.");
    }
  }

  async getGMAPIToken(tokenSet) {
    const now = Math.floor(Date.now() / 1000);
    if (this.currentGMAPIToken && this.currentGMAPIToken.expires_at > now + 5 * 60) {
      if (this.debugMode) console.log("Returning existing valid GM API token");
      return this.currentGMAPIToken;
    }

    if (this.debugMode) console.log("Requesting GM API Token using MS Access Token");
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
        console.warn("Returned GM API token was missing vehicle information. Deleting existing tokens for reauth.");
        if (fs.existsSync(this.MSTokenPath)) fs.renameSync(this.MSTokenPath, `${this.MSTokenPath}.old`);
        if (fs.existsSync(this.GMTokenPath)) fs.renameSync(this.GMTokenPath, `${this.GMTokenPath}.old`);
        this.currentGMAPIToken = null;
        return await this.authenticate();
      }

      gmapiTokenResponse.expires_at = Math.floor(Date.now() / 1000) + parseInt(gmapiTokenResponse.expires_in.toString());
      gmapiTokenResponse.expires_in = parseInt(gmapiTokenResponse.expires_in.toString());

      if (this.debugMode) console.log("Set GM Token expiration to ", gmapiTokenResponse.expires_at);

      this.currentGMAPIToken = gmapiTokenResponse;
      await this.saveTokens(tokenSet);
      return gmapiTokenResponse;
    } catch (error) {
      this.handleRequestError(error, "GM API Token Error");
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
          if (this.debugMode) console.log(`Added cookie: ${cookieString.split(";")[0]}`);
        } catch (error) {
          console.error(`Failed to add cookie: ${cookieString} for URL ${parsedUrl.origin}, Error: ${error.message}`);
        }
      });
    }
  }

  async getRequest(url) {
    try {
      const cookieStringBefore = await this.jar.getCookieString(url);
      if (this.debugMode) {
        console.log("Cookies before GET:", cookieStringBefore);
        console.log("GET URL:", url);
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
      if (this.debugMode) console.log("GET Response status:", response.status, "for URL:", url);
      return response;
    } catch (error) {
      if (error.response && error.response.status !== 302) {
        this.handleRequestError(error, "GET Request Error");
      } else if (!error.response) {
        console.error("GET Request failed without response:", error.message);
      }
      return error.response || { status: error.code, data: error.message, headers: {} };
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
        console.log("Cookies before POST:", cookieString);
        console.log("POST URL:", url);
        console.log("POST data:", formData.toString());
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
      if (this.debugMode) console.log("POST Response status:", response.status, "for URL:", url);
      return response;
    } catch (error) {
      this.handleRequestError(error, "POST Request Error");
      if (error.response) return error.response;
      throw error;
    }
  }

  handleRequestError(error, context = "HTTP Error") {
    if (error.response) {
      console.error(`${context} ${error.response.status}: ${error.response.statusText}`);
      console.error("Error details:", error.response.data);
      if (error.response.status === 401) {
        console.error("Authentication failed. Please check your credentials or token validity.");
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

  async captureRedirectLocation(url) {
    try {
      const cookieStringBefore = await this.jar.getCookieString(url);
      if (this.debugMode) {
        console.log("Cookies before redirect capture:", cookieStringBefore);
        console.log("Redirect capture URL:", url);
      }
      const response = await this.axiosClient.get(url, {
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || (status >= 200 && status < 300),
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.6 Mobile/15E148 Safari/604.1",
          ...(cookieStringBefore && { Cookie: cookieStringBefore }),
        },
      });

      this.processCookieHeaders(response, url);

      if (response.status === 302) {
        const redirectLocation = response.headers["location"];
        if (!redirectLocation) {
          throw new Error("No redirect location found in response headers despite 302 status");
        }
        if (this.debugMode) console.log("Redirect location:", redirectLocation);
        return redirectLocation;
      }
      throw new Error(`Expected a redirect (302) but got status: ${response.status}`);
    } catch (error) {
      if (error.response && error.response.status === 302) {
        this.processCookieHeaders(error.response, url);
        const redirectLocation = error.response.headers["location"];
        if (!redirectLocation) {
          throw new Error("No redirect location found in response headers (error path)");
        }
        if (this.debugMode) console.log("Redirect location (from error path):", redirectLocation);
        return redirectLocation;
      }
      this.handleRequestError(error, "Redirect Capture Error");
      throw error;
    }
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
      if (this.debugMode) console.log("Attempting OpenID discovery from:", discoveryUrl);

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
      if (this.debugMode) console.log("Successfully created issuer with discovery data");
    } catch (error) {
      console.warn("OpenID discovery failed, using fallback configuration", error.message);
      issuerInstance = new this.oidc.Issuer(fallbackConfig);
      if (this.debugMode) console.log("Created issuer with fallback configuration");
    }
    if (!issuerInstance) throw new Error("Failed to create OpenID issuer");
    if (!issuerInstance.authorization_endpoint) throw new Error("Issuer missing authorization_endpoint");

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
    if (this.debugMode) console.log("Starting PKCE auth");
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
      if (!openIdTokenSet.access_token) throw new Error("No access token received");

      const tokenSet = {
        access_token: openIdTokenSet.access_token,
        id_token: openIdTokenSet.id_token,
        refresh_token: openIdTokenSet.refresh_token,
        expires_at: openIdTokenSet.expires_at,
        expires_in: openIdTokenSet.expires_in,
      };
      if (this.debugMode) console.log("MS Access Token obtained.");
      return tokenSet;
    } catch (err) {
      console.error("Failed to obtain MS access token:", err);
      throw err;
    }
  }

  async loadMSToken() {
    if (this.debugMode) console.log("Loading existing MS tokens, if they exist.");
    if (fs.existsSync(this.MSTokenPath)) {
      let storedTokens = null;
      try {
        storedTokens = JSON.parse(fs.readFileSync(this.MSTokenPath, "utf-8"));
      } catch (err) {
        console.warn("Stored MS token was not parseable, getting new token:", err.message);
        return false;
      }

      try {
        const decodedPayload = jwt.decode(storedTokens.access_token);
        const usernameUpper = this.config.username.toUpperCase();
        const tokenUserIdentifier = decodedPayload?.name?.toUpperCase() || decodedPayload?.email?.toUpperCase() || decodedPayload?.upn?.toUpperCase();

        if (!decodedPayload || tokenUserIdentifier !== usernameUpper) {
          if (this.debugMode) console.log(`Stored MS token was for different user (${tokenUserIdentifier} vs ${usernameUpper}), getting new token`);
          return false;
        }
      } catch (jwtError) {
        console.warn("Error decoding stored MS token, getting new token:", jwtError.message);
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      if (storedTokens.expires_at && storedTokens.expires_at > now + 5 * 60) {
        if (this.debugMode) console.log("MS Access token is still valid");
        return storedTokens;
      } else if (storedTokens.refresh_token) {
        if (this.debugMode) console.log("Refreshing MS access token");
        try {
          const client = await this.setupOpenIDClient();
          const refreshedTokens = await client.refresh(storedTokens.refresh_token);
          if (!refreshedTokens.access_token) throw new Error("Refresh token response missing access_token");

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
          console.error("Failed to refresh MS token:", refreshError.message);
          if (refreshError.data) console.error("Refresh error data:", refreshError.data);
          return false;
        }
      } else {
        if (this.debugMode) console.log("MS Token expired and no refresh token available.");
        return false;
      }
    }
    return false;
  }
}

// Wrap the main logic in an async function
async function main() {
  dotenv.config();
  user_email_addr = process.env.EMAIL ?? (await rl.question("Enter OnStar account email address:"));
  user_password = process.env.PASSWORD ?? (await rl.question("Enter OnStar account password:"));
  user_device_uuid = process.env.UUID ?? (await rl.question("Enter Device ID (UUID):"));
  user_vehicle_vin = process.env.VIN ?? (await rl.question("Enter Vehicle VIN:"));
  user_totp_key = process.env.TOTPKEY ?? (await rl.question("Enter TOTP Key/Secret:"));

  if (!user_email_addr || !user_password || !user_device_uuid || !user_totp_key) {
    console.log("Onstar Account Information (Email, Password, Device ID, TOTP Key) must be provided.");
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
    console.log("Starting GM authentication process...");
    const gmapiTokenResponse = await gmAuth.authenticate();

    if (gmapiTokenResponse && gmapiTokenResponse.access_token) {
      console.log("GM Authentication successful. GM API Token obtained.");
      console.log("GM API Access Token (first 10 chars):", gmapiTokenResponse.access_token.substring(0, 10) + "...");
      console.log("GM API Token Expires At:", new Date(gmapiTokenResponse.expires_at * 1000));

      if (user_vehicle_vin) {
        try {
          console.log(`Testing GM API Request for VIN: ${user_vehicle_vin}`);
          await testGMAPIRequestUsingAxios(gmapiTokenResponse, user_vehicle_vin, gmAuth.axiosClient);
        } catch (error) {
          console.error("GM API Test failed:", error.message);
        }
      } else {
        console.log("VIN not provided, skipping API test request.");
      }
    } else {
      console.error("GM Authentication failed to return a valid token.");
    }
  } catch (error) {
    console.error("Overall authentication or API test process failed:", error.message);
    if (error.stack) console.error(error.stack);
  }
  exit();
}

// Test the GM API using the GM API token (rewritten for Axios)
async function testGMAPIRequestUsingAxios(gmapiTokenResponse, vin, axiosInstance) {
  console.log("Testing GM API Request with Axios");
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

    console.log("Diagnostic request successful:", response.data);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`GM API Request Error ${error.response.status}`);
      console.error("Error details:", error.response.data || error.response.statusText);
      if (error.response.status === 401) {
        console.error("Authentication failed for API request. Token may be invalid or expired.");
      }
    } else if (error.request) {
      console.error("No response received from GM API for diagnostic request");
    } else {
      console.error("Request Error (diagnostics):", error.message);
    }
    throw error;
  }
}

// Call the main function
main().catch((error) => {
  console.error("Error in main execution:", error);
  exit(1);
});
