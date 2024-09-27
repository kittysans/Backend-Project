const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail) {
    const authenticateUser = (email, password, done) => {
        const user = getUserByEmail(email)
        if (user == null) {
            return done(null, false, { message: 'No user!'})
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user)
            } else {
                return done(null, false, { message: 'password incorrect'})
            }
        } catch (error) {
            return done(error)
        }
    }

    passport.use(new LocalStrategy({ usernameField: 'email' }), authenticateUser)
    passport.serializUser((user, done) => {  })
    passport.dserializUser((id, done) => {  })
}

module.exports = initialize