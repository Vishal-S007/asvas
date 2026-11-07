// CP-07 end-to-end: dashboard -> Keycloak (authorization code + PKCE) -> password + TOTP enrolment -> API.
// Requires the dev stack (scripts/dev-up.sh with ASVAS_OIDC_ISSUER set), `npm run dev` on :5173 and
// var/keycloak/dev-users.json (written by scripts/keycloak-dev.sh setup). Usage: node e2e/oidc-sso.e2e.cjs <email>
// The browser context ignores TLS errors only because Keycloak uses the development CA; the API verifies it.
const { chromium } = require("playwright");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const email = process.argv[2] || "operator@acme.test";
const users = JSON.parse(fs.readFileSync(path.join(__dirname, "../../var/keycloak/dev-users.json"), "utf8"));
const base32 = (s) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "";
  for (const c of s.replace(/[\s=]/g, "").toUpperCase()) bits += a.indexOf(c).toString(2).padStart(5, "0");
  return Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2))); };
const totp = (secret, t = Date.now()) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac("sha1", base32(secret)).update(c).digest(); const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0"); };
const step = (m) => console.log("STEP", m);

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true });
  const p = await ctx.newPage();
  const errors = []; p.on("pageerror", (e) => errors.push(String(e)));
  await p.goto("http://localhost:5173/");
  await p.getByRole("button", { name: "Sign in with SSO" }).click();
  await p.waitForURL(/localhost:8443\/realms\/asvas/);
  step("redirected to Keycloak with PKCE: " + new URL(p.url()).searchParams.get("code_challenge_method"));
  await p.fill("#username", email); await p.fill("#password", users[email].password);
  await p.click("#kc-login");
  let secret = users[email].totp_secret;
  await p.waitForSelector("#totp, #otp");
  if (await p.locator("#totp").count()) {
    await p.click("#mode-manual");
    secret = (await p.locator("#kc-totp-secret-key").innerText()).trim();
    await p.fill("#totp", totp(secret));
    await p.fill("#userLabel", "e2e");
    await p.click("#saveTOTPBtn");
    users[email].totp_secret = secret;
    fs.writeFileSync(path.join(__dirname, "../../var/keycloak/dev-users.json"), JSON.stringify(users, null, 1), { mode: 0o600 });
    step("TOTP authenticator enrolled (required action, secret read from the manual-entry view)");
    // Enrolment alone does not put "otp" in the token's amr claim, so the API refuses that first token.
    await p.waitForSelector("text=sign in once more");
    step("API refused the enrolment-only token (no otp in amr); signing in again with a code");
    await p.getByRole("button", { name: "Sign in with SSO" }).click();
    await p.waitForSelector("#password, #otp");
    if (await p.locator("#password").count()) {  // prompt=login: full re-authentication
      if (await p.locator("#username").isEditable().catch(() => false)) await p.fill("#username", email);
      await p.fill("#password", users[email].password); await p.click("#kc-login");
      await p.waitForSelector("#otp");
    }
    const left = 30000 - (Date.now() % 30000); await p.waitForTimeout(left + 500); // fresh window: codes are single-use
    await p.fill("#otp", totp(secret)); await p.click("#kc-login");
  } else {
    await p.waitForSelector("#otp");
    // avoid re-using a code from a previous run within the same 30 s window
    const left = 30000 - (Date.now() % 30000); if (left < 5000) await p.waitForTimeout(left + 500);
    await p.fill("#otp", totp(secret)); await p.click("#kc-login");
    step("signed in with password + TOTP");
  }
  await p.waitForURL("http://localhost:5173/assessments", { timeout: 20000 });
  const who = await p.locator(".whoami").innerText();
  step("dashboard session: " + who.replace(/\s+/g, " "));
  const token = await p.evaluate(() => sessionStorage.getItem("asvas.token") || Object.values(sessionStorage).find((v) => v.split(".").length === 3));
  const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
  step(`token iss=${claims.iss} aud=${JSON.stringify(claims.aud)} amr=${JSON.stringify(claims.amr)} azp=${claims.azp}`);
  const me = await p.evaluate(async () => (await fetch("/api/v1/me", { headers: { Authorization: "Bearer " + (sessionStorage.getItem("asvas.token") || Object.values(sessionStorage).find((v) => v.split(".").length === 3)) } })).json());
  step("API /me -> " + JSON.stringify(me));
  console.log(errors.length ? "PAGE ERRORS " + errors : "no page errors");
  await b.close();
  if (me.email !== email) process.exit(1);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
