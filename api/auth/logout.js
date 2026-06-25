const A = require("../_auth");
module.exports = async function (req, res) {
  res.setHeader("Set-Cookie", A.clearCookie("ps_session"));
  res.statusCode = 302;
  res.setHeader("Location", "/");
  res.end();
};
