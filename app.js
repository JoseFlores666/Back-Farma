const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session'); 
const MySQLStore = require('express-mysql-session')(session); 
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();

const app = express();

app.use(cors());


const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    clearExpired: true, 
    checkExpirationInterval: 900000, 
    expiration: 86400000, 
});

app.use(
    session({
        key: 'sessionId', 
        secret: process.env.SESSION_SECRET || 'yourSecret', 
        store: sessionStore,
        resave: false,
        saveUninitialized: false, 
        cookie: {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Strict',
            maxAge: 30 * 60 * 1000, 
        },
    })
);

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json({ limit: '10mb' }));

app.use('/api', authRoutes);

module.exports = app;
