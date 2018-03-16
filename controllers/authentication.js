const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function userToken(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
};

exports.signin = function(req, res, next) {
  res.send({ token: userToken(req.user) });
};

exports.signup = function(req, res, next) {

  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'Email and password are required!' })
  }

  // See if a user with this email exists
  User.findOne({ email: email }, function(error, existingUser) {
    if (error) { return next(err); }

    // If a user exists, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is already in use' });
    }

    // If not, create and save user record
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(error) {
      if (error) { return next(error); } 

      // Respond to request indicating the user was created
      res.json({ token: userToken(user) });
    });
  });
}
