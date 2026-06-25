const A = require("./_auth");
const DATA = {
  "sample-data-report": `SELECT
  month,
  year23,
  year24,
  (year24 - year23) AS change,
  ROUND(
    CAST(year24 - year23 AS DOUBLE) / NULLIF(year23, 0) * 100,
    2
  ) AS pct_change
FROM peaka."table"."lookup table"
ORDER BY month
LIMIT 100`
};

module.exports = async function (req, res) {
  res.setHeader("Content-Type", "application/json");
  let s = A.readSession(req);
  if (!s) { res.statusCode = 401; res.end(JSON.stringify({ error: "Not authenticated", rows: [] })); return; }
  const now = Math.floor(Date.now() / 1000);
  if (s.refresh_token && s.expires_at && s.expires_at - now < 60) {
    const tok = await A.refresh(s.refresh_token);
    if (!tok) { res.statusCode = 401; res.end(JSON.stringify({ error: "Session expired", rows: [] })); return; }
    s = { access_token: tok.access_token, refresh_token: tok.refresh_token || s.refresh_token, expires_at: now + (tok.expires_in || 300), user: s.user };
    res.setHeader("Set-Cookie", A.cookie("ps_session", A.seal(s, 604800), 604800));
  }
  const q = req.query && req.query.report;
  const report = Array.isArray(q) ? q[0] : q;
  const SQL = report && Object.prototype.hasOwnProperty.call(DATA, report) ? DATA[report] : null;
  if (!SQL) { res.statusCode = 404; res.end(JSON.stringify({ rows: [] })); return; }
  try {
    const base = (process.env.PEAKA_PARTNER_API_BASE_URL || "").replace(/\/$/, "");
    const url = base + "/data/projects/" + process.env.PEAKA_PROJECT_ID + "/queries/execute?format=SIMPLE";
    const r = await fetch(url, {
      method: "POST",
      headers: { "Authorization": "Bearer " + s.access_token, "Content-Type": "application/json" },
      body: JSON.stringify({ statement: SQL }),
    });
    const payload = await r.json();
    const raw = Array.isArray(payload) ? payload : (payload.data || payload.rows || []);
    res.status(r.ok ? 200 : r.status).json({ rows: raw });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
};
