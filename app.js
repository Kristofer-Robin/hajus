const express = require('express');
const cookieParser = require("cookie-parser");
const sessions = require('express-session');
const http = require('http');
var parseUrl = require('body-parser');
const app = express();
const bcrypt = require('bcrypt');
var mysql = require('mysql2');
const { encode } = require('punycode');
const winston = require('winston');
const winstonMysql = require('winston-mysql');

let encodeUrl = parseUrl.urlencoded({ extended: false });

//session middleware
app.use(sessions({
    secret: "kys",
    saveUninitialized:true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 24 hours
    resave: false
}));

app.use(cookieParser());

// Correct the path to the 'minesweeper' directory if necessary
app.use('/minesweeper', express.static('minesweeper'));

// Add a new route for the Minesweeper game
app.get('/minesweeper', (req, res) => {
    // Check if the user is logged in before serving the game
    if (req.session.user && req.session.user.username) {
        res.sendFile(__dirname + '/minesweeper/index.html');
    } else {
        // If not logged in, redirect to the login page
        res.redirect('/login-page');
    }
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.json()
    ),
    transports: [
        new winstonMysql({
            host: 'localhost',
            user: 'root',
            password: 'qwerty',
            database: 'login',
            table: 'logs'
        })
    ],
});

logger.info('This is a test log message.');

var con = mysql.createConnection({
    host: "localhost",
    user: "root", // my username
    password: "qwerty", // my password
    database: "login"
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/register.html');
})

app.post('/register', encodeUrl, (req, res) => {
    var userName = req.body.userName;
    var password = req.body.password;
    var email = req.body.email;

    con.connect(function(err) {
        if (err){
            console.log(err);
        }
        // checking user already registered or no
        con.query(`SELECT * FROM users WHERE username = '${userName}' AND password  = '${password}'`, function(err, result){
            if(err){
                console.log(err);
            }
            if(Object.keys(result).length > 0){
                res.sendFile(__dirname + '/failReg.html');
            }else{
                //creating user page in userPage function
                function userPage(){
                    // We create a session for the dashboard (user page) page and save the user data to this session:
                    req.session.user = {
                        username: userName,
                        password: password,
                        email: email
                    };

                    res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <title>Login and register form with Node.js, Express.js and MySQL</title>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body>
                    <div class="container">
                        <h3>Hi, ${req.session.user.username} ${req.session.user.email}</h3>
                        <a href="/">Log out</a>
                    </div>
                </body>
                </html>
                `);
                }
                // inserting new user data
                // Generate a salt and hash the password
                bcrypt.hash(password, 10, function(err, hash) {
                    if (err) {
                        console.log(err);
                        // Handle error appropriately
                    } else {
                        // Insert the user with the hashed password into the database
                        var sql = `INSERT INTO users (username, password, email) VALUES ('${userName}', '${hash}', '${email}')`;
                        con.query(sql, function (err, result) {
                            if (err){
                                console.log(err);
                            } else {
                                // Call userPage() after successful registration
                                userPage();
                            }
                        });
                    }
                });
            }
        });
    });
});

app.post("/login", encodeUrl, (req, res) => {
    var userName = req.body.userName;
    var password = req.body.password;

    con.connect(function (err) {
        if (err) {
            console.log(err);
        }
        con.query(`SELECT * FROM users WHERE username = ?`, [userName], function (err, result) {
            if (err) {
                console.log(err);
                // Consider logging this error with your logger as well
                return res.status(500).send("Server error");
            }

            if (result.length === 1) {
                const storedHash = result[0].password;
                const email = result[0].email;

                // Compare the provided password with the stored hash using bcrypt
                bcrypt.compare(password, storedHash, function (err, bcryptResult) {
                    if (err) {
                        console.error(err);
                        insertLog('error', `Error comparing password for login: ${err.message}`);
                        return res.status(500).send("Server error");
                    } else if (bcryptResult) {
                        insertLog('info', `User logged in: ${userName}`);
                        // Passwords match, user is authenticated
                        req.session.user = {
                            email: email,
                            username: userName,
                            // It is not recommended to save the password hash in the session.
                            // password: storedHash
                        };
                        logger.info(`User logged in: ${userName}`); // Log the successful login
                        res.redirect('/dashboard'); // Redirect to the dashboard route
                    } else {
                        insertLog('warn', `Failed login attempt for username: ${userName}`);
                        // Passwords do not match, login failed
                        res.sendFile(path.join(__dirname, 'failLog.html'));
                    }
                });
            } else {
                // User not found, login failed
                res.sendFile(path.join(__dirname, 'failLog.html'));
            }
        });
    });
});

function insertLog(level, message) {
    const logEntry = {
        level: level,
        message: message,
        timestamp: new Date()  // This will automatically be formatted to your SQL datetime format
    };

    const query = 'INSERT INTO logs (level, message, timestamp) VALUES (?, ?, ?)';
    con.query(query, [logEntry.level, logEntry.message, logEntry.timestamp], (err, results) => {
        if (err) {
            console.error('Failed to insert log into database', err);
        }
    });
}




app.get('/dashboard', (req, res) => {
    if (req.session.user && req.session.user.username) {
        // User is authenticated, send the dashboard page
        res.sendFile(__dirname + '/dashboard.html');
    } else {
        // User is not authenticated, redirect to the login page
        res.redirect('/login-page');
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy(function(err) {
        res.redirect('/login-page');
    });
});

app.get('/login-page', (req, res) => {
    res.sendFile(__dirname + '/login.html');
});


app.listen(3006, ()=>{
    console.log("Server running on port 3006");
    console.log("Server running at http://localhost:3006/");
});
