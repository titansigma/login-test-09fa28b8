const A = require("../_auth");
module.exports = async function (req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const started = await A.authStart(url.searchParams.get("returnTo") || "/");
    res.setHeader("Set-Cookie", A.cookie("ps_tx", started.tx, 600));
    res.statusCode = 302;
    res.setHeader("Location", started.url);
    res.end();
  } catch (e) {
    res.statusCode = 500;
    res.end("Login error");
  }
};
