const express = require('express');
const path = require('path');
const app = express();
require("dotenv").config();
const db = require("./database");

const bcrypt = require("bcrypt");
const bodyParser = require('body-parser');
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASS;


// Connect to the database
db.connect((err) => {
    if (err) console.log(err);
    else console.log("connected to the database.")
});


// Configuring express
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public/css'));
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());


// Hashing utitlities
const hashPass = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);

    return { "salt": salt, "hash": hash };
}

const matchPass = async (pass, salt, existingHash) => await bcrypt.hash(pass, salt) === existingHash;


// Routes
app.get('/', function (req, res) {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login', data = { registered: req.query.registered });
})
app.get('/register', (req, res) => {
    res.render('register', data = {});
})

app.post('/register', async (req, res) => {
    let { username, password, confirmPassword, adminPasscode } = req.body;
    let regAsAdmin = Object.keys(req.body).includes("registerAsAdmin");
    let adminApproved = (regAsAdmin && adminPasscode == ADMIN_PASS);

    db.query(
        `select * from users where username = ${db.escape(username)}`,
        async (err, result) => {
            if (err) res.send(err);
            else {
                if (result.length) res.render('register', data = { error: "User already exists" });
                else if (password != confirmPassword) res.render('register', data = { error: "The passwords don't match" });
                else if (regAsAdmin && !adminApproved) res.render('register', data = { error: "Incorrect Admin Passcode" })
                else {
                    let { hash, salt } = await hashPass(password);
                    db.query(
                        `insert into users(username, admin, hash, salt) 
                            values(${db.escape(username)}, ${db.escape(regAsAdmin)}, ${db.escape(hash)}, ${db.escape(salt)})`,
                        (err, result) => {
                            if (err) res.json(err);
                            else res.redirect('/login?registered=true');
                        }
                    )
                }
            }
        }
    )

})

app.post('/login', async (req, res) => {
    let { username, password } = req.body;
    db.query(
        `select * from users where username=${db.escape(username)}`,
        async (err, result) => {
            if (result.length == 0) res.render('login', data={error: "User doesn't exist"})
            else {
                let passMatch = await matchPass(password, result[0].salt, result[0].hash);
                if (passMatch) res.send("Authenticated");
                else res.render('login', data = {error: "Incorrect username or password"});
            } 
        }
    )
}) 

app.listen(PORT, () => {
    console.log(`The server is running on http://localhost:${PORT}`)
});