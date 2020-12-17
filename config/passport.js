require('dotenv').config();

// Passport strategy for authenticating with a JSON web token - Authenticates endpoints using a token
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const options = {};
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.secretOrKey = process.env.JWT_SECRET;

module.exports = (passport) => {
    passport.use(new JwtStrategy(options, (jwt_payload, done) => {
        // Have a user that will be found in the payload then we will check to see if the user is in the database
    }))
}