require('dotenv').config();

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken'); //require jsonwebtoken library
const cors = require('cors');
const path = require('path');

app.use(express.json()); //give the server the ability to parse JSON
app.use(cors());
app.use(express.static('views'));

app.set('view engine', 'ejs');
app.set('views', './views');



//For the purposes of this project, refresh tokens are stored in an array - Normally, they  would be stored in a database
let refreshTokens = [];

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401); //if the refresh token is null, send a 401 status
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403); //if the refresh token is not in the refreshTokens array, send a 403 status

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); //if the refresh token is invalid, send a 403 status
        const accessToken = generateAccessToken({name: user.name}); //generate an access token
        res.json({accessToken: accessToken}); //send the access token to the client
    });
});

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token); //remove the refresh token from the refreshTokens array
    res.sendStatus(204); //send a 204 status
});

app.post('/login', async (req, res) => {
    const username = req.body.username;
    
    try {
        // Verify user exists in SSO server
        const response = await fetch('http://localhost:3001/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });

        const data = await response.json();
        
        if (!response.ok || !data.valid) {
            return res.status(401).json({ error: 'Invalid username' });
        }

        // If user is valid, generate tokens
        const user = { name: username };
        const accessToken = generateAccessToken(user);
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
        refreshTokens.push(refreshToken);
        
        res.json({ accessToken, refreshToken });
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});


/*"Generate an access token for the user with a 15 second expiration time"*/
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'});
}

function checkSSOAuthenticated(req, res, next) {
    const token = req.query.token; //get the token from the request query
    if (!token) return res.redirect('/sso-login'); //if the token is null, redirect to the sso-login page

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.redirect('/sso-login'); //if the token is invalid, redirect to the sso-login page
        req.user = user; //set the user to the user object
        next(); //pass the user to the next middleware
    });
}

//set up home page route
app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', {name: req.user.name}); //
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
    if (req.isAuthenticated()) { //if the user is authenticated, redirect to the home page
        return res.redirect('/');
    }
    next();
}

function checkNotSSOAuthenticated(req, res, next) {
    const token = req.query.token; //get the token from the request query
    if (!token) return next(); //if the token is null, pass the request to the next middleware

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (!err) return res.redirect('/sso-index?token=' + token);
        next();
    });
}

app.get('/sso-login', checkNotSSOAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'sso-login.html'));
});

app.get('/welcome', checkNotSSOAuthenticated, (req, res) => {
    res.redirect('http://localhost:3000/welcome');
});


app.get('/sso-login-success', checkSSOAuthenticated, (req, res) => {
    const token = req.query.token;
    const username = req.query.username;
    
    res.render('sso-login-success', {
        user: { name: username },
        accessToken: token
    });
});

app.get('/sso-index', checkSSOAuthenticated, (req, res) => {
    res.render('index', { 
        name: req.user.name 
    });
});

app.listen(4000, () => {
    console.log('sso-server is running on port 4000');
});

