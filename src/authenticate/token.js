const jwt = require('jsonwebtoken');
const { secret } = require('../config/auth.json');

module.exports = (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth) {
    return res.status(401).json({
        status: "Unauthorized",
        message: "No provided token."
    })
  }

  const authParts = auth.split(' ');

  if (authParts.length != 2 && authParts[0] != 'Bearer') {
    return res.status(401).json({
        status: "Unauthorized",
        message: "Invalid token."
    })
  }

  jwt.verify(authParts[1], secret, (err, jwt) => {
    if (err) {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Invalid token."
        })
      }

      console.log(jwt)

    if (jwt.type != 'login') {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Invalid token."
        })
      }

    req.userId = jwt.id;
    return next();
  });
};