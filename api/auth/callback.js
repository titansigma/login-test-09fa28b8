const A = require("../_auth");
module.exports = async function (req, res) {
  const url = new URL(req.url, "http://localhost");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const tx = A.open(A.parseCookies(req).ps_tx);
  const cookies = [A.clearCookie("ps_tx")];
  if (!code || !state || !tx || state !== tx.state) {
    res.setHeader("Set-Cookie", cookies);
    res.statusCode = 400;
    res.end("Invalid or expired login. Please try again.");
    return;
  }
  try {
    const redirectUri = (process.env.APP_BASE_URL || "").replace(/\/$/, "") + "/api/auth/callback";
    const tok = await A.exchange(code, redirectUri, tx.verifier);
    const ok = await A.hasProjectAccess(tok.access_token, process.env.PEAKA_PROJECT_ID);
    if (!ok) {
      res.setHeader("Set-Cookie", cookies);
      res.statusCode = 403;
      res.setHeader("Content-Type", "text/html");
      res.end(A.deniedHtml());
      return;
    }
    const session = {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      expires_at: Math.floor(Date.now() / 1000) + (tok.expires_in || 300),
      user: A.claims(tok.access_token),
    };
    cookies.push(A.cookie("ps_session", A.seal(session, 604800), 604800));
    res.setHeader("Set-Cookie", cookies);
    res.statusCode = 302;
    res.setHeader("Location", tx.returnTo || "/");
    res.end();
  } catch (e) {
    res.setHeader("Set-Cookie", cookies);
    res.statusCode = 500;
    res.end("Authentication failed");
  }
};
