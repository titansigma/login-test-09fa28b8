const A = require("../_auth");
module.exports = async function (req, res) {
  const s = A.readSession(req);
  res.setHeader("Content-Type", "application/json");
  if (!s) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: "Not authenticated" }));
    return;
  }
  res.statusCode = 200;
  res.end(JSON.stringify({ user: s.user || null }));
};
