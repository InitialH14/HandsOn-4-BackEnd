const passport = require('passport');
const { Strategy, ExtractJwt } = require('passport-jwt');
const userQuery = require('../database/mongodb/query');


const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET, 
    expiresIn: '30m' 
  };
  
  passport.use(new Strategy(options, async (jwt, done) => {
    try {
      const user = await userQuery.findOneByEmail(jwt.email); 
      if (user) {
        return done(null, user);
      }
      return done(null, false, { message: 'Token has expired' });
    } catch (error) {
      return done(error, false, { message: 'Failed to authenticate token' });
    }
  }));
  
  const initializePassport = () => {
    return passport.initialize();
  };
  
  const authenticatePassportJwt = () => {
    return passport.authenticate('jwt', { session: false });
  };
  
  module.exports = {
    initializePassport,
    authenticatePassportJwt
  };