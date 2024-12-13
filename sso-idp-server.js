require('dotenv').config();

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken'); //require jsonwebtoken library

app.use(express.json()); //give the server the ability to parse JSON

const users = [
    {
        username: 'John 117',
        title: 'Post 1'
    },
    {
        username: 'Master Chief',
        title: 'Post 2'
    }
];

// Authentication endpoint
app.post('/authenticate', (req, res) => {
    const username = req.body.username;
    const user = users.find(u => u.username === username);
    
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    res.json({ valid: true, user: user });
});

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name));
});


/*Get user, authenticate token, and pass it to the next middleware*/
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; //split the string into an array and get the second element
    if (token == null) return res.sendStatus(401); //if the token is null, send a 401 status

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); //if user has token butthe token is invalid, send a 403 status
        req.user = user; //set the user to the user object
        next(); //pass the user to the next middleware
    });
}

app.listen(3001, () => {
    console.log('sso-server is running on port 3001');
});

