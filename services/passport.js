const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Setup option for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT strategy for signup
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  User.findById(payload.sub, function(error, user){
    if (error) { return done(error, false); }

    if (user) { done(null, user); }
    else { done(null, false); }
  });
});

// Create local strategy for signin
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  User.findOne({ email: email }, function(error, user) {
    if (error) { return done(error); }
    if (!user) { return done(null, false); }

    // Compare passwords - is 'password' equal to user.password
    user.comparePassword(password, function(error, isMatch) {
      if (error) { return done(error); }
      if (!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });
});

// Tell Passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);