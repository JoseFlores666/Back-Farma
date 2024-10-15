const session = require('express-session');

module.exports = {
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true, 
        sameSite: 'Strict',
        maxAge: 30 * 60 * 1000 
    }
};
