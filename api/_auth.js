const crypto = require("crypto");

function sha256(buf) { return crypto.createHash("sha256").update(buf).digest(); }
function key() { return sha256(process.env.SESSION_SECRET || ""); }

// AES-256-GCM sealed cookie value: base64url(iv[12] | tag[16] | ciphertext), payload carries exp.
function seal(obj, maxAgeSec) {
  const payload = JSON.stringify({ d: obj, exp: Math.floor(Date.now() / 1000) + maxAgeSec });
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key(), iv);
  const ct = Buffer.concat([c.update(payload, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64url");
}
function open(token) {
  if (!token) return null;
  try {
    const buf = Buffer.from(token, "base64url");
    const d = crypto.createDecipheriv("aes-256-gcm", key(), buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    const pt = Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8");
    const parsed = JSON.parse(pt);
    if (!parsed.exp || parsed.exp < Math.floor(Date.now() / 1000)) return null;
    return parsed.d;
  } catch (e) { return null; }
}

function randomString() { return crypto.randomBytes(32).toString("base64url"); }
function challenge(verifier) { return sha256(verifier).toString("base64url"); }

function parseCookies(req) {
  const h = (req.headers && req.headers.cookie) || "";
  const out = {};
  h.split(";").forEach(function (p) {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function cookie(name, val, maxAgeSec) {
  return name + "=" + encodeURIComponent(val) + "; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=" + maxAgeSec;
}
function clearCookie(name) {
  return name + "=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0";
}
function readSession(req) { return open(parseCookies(req).ps_session); }

let _cfg;
async function config() {
  if (_cfg) return _cfg;
  const base = (process.env.OAUTH_AUTHORIZATION_SERVER_URL || "").replace(/\/$/, "");
  const r = await fetch(base + "/.well-known/oauth-authorization-server", { cache: "no-store" });
  if (!r.ok) throw new Error("OAuth discovery failed: " + r.status);
  _cfg = await r.json();
  return _cfg;
}
function basicAuth() {
  return Buffer.from((process.env.OAUTH_CLIENT_ID || "") + ":" + (process.env.OAUTH_CLIENT_SECRET || "")).toString("base64");
}
async function exchange(code, redirectUri, verifier) {
  const cfg = await config();
  const r = await fetch(cfg.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + basicAuth() },
    body: new URLSearchParams({ grant_type: "authorization_code", code: code, redirect_uri: redirectUri, code_verifier: verifier }),
  });
  if (!r.ok) throw new Error("Token exchange failed: " + r.status);
  return r.json();
}
async function refresh(refreshToken) {
  const cfg = await config();
  const r = await fetch(cfg.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + basicAuth() },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
  });
  if (!r.ok) return null;
  return r.json();
}
function claims(token) {
  try { return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8")); }
  catch (e) { return {}; }
}
async function authStart(returnTo) {
  const cfg = await config();
  const verifier = randomString();
  const state = randomString();
  const redirectUri = (process.env.APP_BASE_URL || "").replace(/\/$/, "") + "/api/auth/callback";
  const u = new URL(cfg.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", process.env.OAUTH_CLIENT_ID || "");
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", process.env.OAUTH_SCOPE || "user_access");
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", challenge(verifier));
  u.searchParams.set("code_challenge_method", "S256");
  return { url: u.toString(), tx: seal({ verifier: verifier, state: state, returnTo: returnTo || "/" }, 600) };
}
// Verify the viewer can access the project (enumerate their accessible Peaka projects).
async function hasProjectAccess(token, projectId) {
  const base = (process.env.PEAKA_PARTNER_API_BASE_URL || "").replace(/\/$/, "");
  const h = { Authorization: "Bearer " + token };
  try {
    const orgs = await (await fetch(base + "/organizations", { headers: h, cache: "no-store" })).json();
    for (const org of orgs) {
      const wss = await (await fetch(base + "/organizations/" + org.id + "/workspaces", { headers: h, cache: "no-store" })).json();
      for (const ws of wss) {
        const projs = await (await fetch(base + "/organizations/" + org.id + "/workspaces/" + ws.id + "/projects", { headers: h, cache: "no-store" })).json();
        if (Array.isArray(projs) && projs.some(function (p) { return p.id === projectId; })) return true;
      }
    }
  } catch (e) {}
  return false;
}
function deniedHtml() {
  return "<!DOCTYPE html><html><head><meta charset=utf-8><title>No access</title><style>body{margin:0;background:#0b0f19;color:#e5e7eb;font:16px/1.5 system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}div{max-width:380px;padding:24px}a{color:#a5b4fc}</style></head><body><div><h1>No access</h1><p>Your Peaka account doesn't have access to this project's data.</p><p><a href=\"/api/auth/logout\">Sign in as someone else</a></p></div></body></html>";
}

module.exports = { seal, open, randomString, challenge, parseCookies, cookie, clearCookie, readSession, config, exchange, refresh, claims, authStart, hasProjectAccess, deniedHtml };
