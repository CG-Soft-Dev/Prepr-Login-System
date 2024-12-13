if (process.env.NODE_ENV !== 'production') { //
    require('dotenv').config();
}

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");//bcrypt is a library for hashing passwords
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const path = require('path');
const jwt = require('jsonwebtoken');

app.use(express.static('views'));

const initializePassport = require('./passport-config');
initializePassport(
    passport, 
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
);

//using local variable to store users for the purposes of this project.
//A database would be used in a real-world application.
const users = [];

//set up view engine, so we can use ejs (this is why ejs dependency is installed)
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET, //secret key for the session
    resave: false, //don't save session if nothing has changed
    saveUninitialized: false //don't save session if it's not initialized
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

// Add this middleware to verify SSO tokens
function verifySSOToken(req, res, next) {
    const token = req.query.token;
    if (!token) return next();

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return next();
        req.ssoUser = user;
        next();
    });
}

// Modify the index route to handle both authentication types
app.get('/', verifySSOToken, (req, res) => {
    if (req.isAuthenticated()) {
        // Passport user
        res.render('index.ejs', { name: req.user.name });
    } else if (req.ssoUser) {
        // SSO user
        res.render('index.ejs', { name: req.ssoUser.name });
    } else {
        res.redirect('/welcome');
    }
});

//set up login page route - "accessing the login page"
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

//set up login post route - "act of logging in"
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

//Not needed since we are using the passport authentication middleware
//set up login post route
/*app.post('/login', (req, res) => {
    console.log(req.body);
    res.send('Logged in');
});*/


//set up register page route - "accessing the register page"
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

//set up register post route - "act of registering"
app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        //push the new user to the users array
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        res.redirect('/login'); //redirect to login page after registering
    } catch {
        res.redirect('/register'); //redirect to register page if there is an error
    }

    console.log(users); //See if the user was added to the users array
});

app.delete('/logout', (req, res, next) => {
    req.logOut((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/welcome'); 
    }); //log out the user - provided by passport
});

//check if the user is authenticated (middleware)
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { 
        return next();
    }
    res.redirect('/login');
}

//check if the user is not authenticated (middleware)
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

app.get('/welcome', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
});

app.get('/sso-login', (req, res) => {
    // Redirect to the SSO authentication endpoint
    res.redirect('http://localhost:4000/sso-login');
});

// Add SSO success route to passport-server
app.get('/sso-login-success', verifySSOToken, (req, res) => {
    if (!req.ssoUser) return res.redirect('/welcome');
    
    res.render('sso-login-success', {
        user: req.ssoUser,
        accessToken: req.query.token
    });
});

app.listen(3000); /* 3000 is the port number, we now have an application running on port 3000 */

/*debugger */