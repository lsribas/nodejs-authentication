const jwt = require('jsonwebtoken');
const { secret } = require('../config/auth.json');
const User = require('../database/user');

module.exports = async (req, res, next) => {
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

  jwt.verify(authParts[1], secret, async (err, jwt) => {
    if (err) {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Invalid token."
        })
      }

    if (jwt.type != 'login') {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Invalid token."
        })
      }

    const _id = jwt.id;
    const user = await User.findOne({ _id }).select('+password');

    if(!user || jwt.password != user.password) {
        return res.status(401).json({
            status: "Unauthorized",
            message: "Expired token."
        })
    }

    user.password = undefined;

    req.user = user;
    return next();
  });
};