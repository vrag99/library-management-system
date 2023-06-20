const express = require('express');
const path = require('path');
const app = express();
require("dotenv").config();
const db = require("./database");

const bcrypt = require("bcrypt");
const bodyParser = require('body-parser');
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
var cookieParser = require('cookie-parser');
const { Console } = require('console');

const PORT = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASS;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;


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
app.use(cookieParser());


var loggedin = false;

// Utilities
const hashPass = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);

    return { "salt": salt, "hash": hash };
}

const matchPass = async (pass, salt, existingHash) => await bcrypt.hash(pass, salt) === existingHash;

const sendErr = (res, code, msg) => res.status(code).json({ error: msg });

function execSql(query, params) {
    return new Promise((resolve, reject) => {
        db.query(query, params, (error, results) => {
            if (error) {
                console.error(error);
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}


const validateJWT = (req, res, next) => {
    const token = req.cookies['access-token'];
    if (token == null) res.redirect('/login');
    else {
        jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) sendErr(res, 403, "error during validation");
            req.user = user;
            next();
        })
    }
}

// Routes
app.get('/', (req, res) => res.render('home'));


app.get('/login', (req, res) => {
    token = req.cookies['access-token'];
    let usr = undefined;
    if (token) {
        jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
            usr = user;
        })
    }
    if (usr) {
        if (usr.admin) res.redirect('/adminDashboard');
        else res.redirect('/userDashboard');
    }
    res.render('login', data = { registered: req.query.registered })
});


app.get('/register', (req, res) => res.render('register', data = {}));


// UserDashboard
app.get('/userDashboard/:mode?', validateJWT, async (req, res) => {

    userID = req.user.id
    mode = req.params.mode

    if (mode) {
        if (mode == 'requested') {
            books = await execSql(`
                select b.*
                from books b
                inner join requests r on b.id = r.book_id
                where r.status = 'request-issue' and r.user_id = ? and b.available_qty>=1;
            `, [userID]);

            res.render('userDashboard', data = {
                username: req.user.name,
                state: mode,
                books: books
            })

        } else if (mode == 'issued') {
            books = await execSql(`
                select b.*
                from books b
                inner join requests r on b.id = r.book_id
                where r.status = 'issued' and r.user_id = ? and b.available_qty>=1;
            `, [userID]);

            res.render('userDashboard', data = {
                username: req.user.name,
                state: mode,
                books: books
            })

        } else if (mode == 'to-be-returned') {
            books = await execSql(`
                select b.*
                from books b
                inner join requests r on b.id = r.book_id
                where r.status = 'request-return' and r.user_id = ? and b.available_qty>=1;
            `, [userID]);

            res.render('userDashboard', data = {
                username: req.user.name,
                state: mode,
                books: books
            })

        }
    }
    else {
        books = await execSql(`
            select b.*
            from books b
            left join requests r on b.id = r.book_id
            and r.user_id = ${db.escape(userID)}
            where r.id is NULL and available_qty>=1;
        `);

        res.render("userDashboard.ejs", data = {
            username: req.user.name,
            state: 'available',
            books: books
        })
    }
})

app.get('/userDashboard/request/:id', validateJWT, async (req, res) => {

    let userID = req.user.id
    await execSql(`
        insert into requests(status, book_id, user_id) 
        values('request-issue', ${db.escape(parseInt(req.params.id))}, ${userID});
    `);
    res.redirect('/userDashboard/requested');
})

app.get('/userDashboard/req-return/:id', validateJWT, async (req, res) => {

    let userID = req.user.id
    await execSql(`
        delete from requests
        where status='issued' and book_id=${db.escape(req.params.id)} and user_id=${db.escape(userID)}
    `)
    await execSql(` 
        insert into requests(status, book_id, user_id) 
        values('request-return', ${db.escape(req.params.id)}, ${db.escape(userID)});
    `);
    res.redirect('/userDashboard/to-be-returned');
})

// AdminDashboard
app.get('/adminDashboard', validateJWT, async (req, res) => {
    console.log(Object.keys(req.query).length)

    if (Object.keys(req.query).length != 0) {
        if (req.query.addedQty) {
            let { id, addedQty } = req.query;
            await execSql(`
                update books 
                set quantity = quantity + ${db.escape(addedQty)}, available_qty = available_qty + ${db.escape(addedQty)}
                where id = ${db.escape(id)} 
            `)
            res.status(200).send("added")
        } else if (req.query.rmQty) {
            let { id, rmQty } = req.query;
            let [{ 'available_qty': qty }] = await execSql(`select available_qty from books where books.id = ${db.escape(id)}`);
            let [{ 'count(*)': requests }] = await execSql(`select count(*) from requests r where r.book_id = ${db.escape(id)}`);

            if (qty - requests >= rmQty) {
                await execSql(`
                update books 
                set quantity = quantity - ${db.escape(rmQty)}, available_qty = available_qty - ${db.escape(rmQty)}
                where id = ${db.escape(id)};
            `)
            res.status(200).send("removed")
            } else {
                console.log(qty - requests >= rmQty)
                res.status(400).send("damn it")
            }
        }
    } else {
        console.log('abcd')
        books = await execSql(`select * from books where quantity>=1;`);
        data = {
            username: req.user.name,
            state: 'all',
            books: books
        };

        if (req.query.duplicateBookEntry) data.error = 'duplicateBookEntry';

        res.render('adminDashboard', data)
    }
});

app.post('/adminDashboard', validateJWT, async (req, res) => {
    let { bookName, bookQty } = req.body;
    let results = await execSql(`select * from books where book_name = ${db.escape(bookName)}`);
    if (results.length === 0) {
        await execSql(`
            insert into books (book_name, quantity, available_qty) values (${db.escape(bookName)}, ${db.escape(bookQty)}, ${db.escape(bookQty)})
        `)
        res.redirect('/adminDashboard')
    } else {
        res.redirect('/adminDashboard?duplicateBookEntry=true')
    }
})

app.get('/adminDashboard/issue-requests/:action?/:id?', validateJWT, async (req, res) => {
    let { action, id } = req.params;
    if (action && id) {
        if (action == 'accept') {
            await execSql(`
                update requests set status = 'issued' 
                where id = ${db.escape(id)};
            `)
            let bookId = await execSql(`select r.book_id from requests r where r.id = ${db.escape(id)}`);
            bookId = bookId[0].book_id;

            await execSql(`
                update books
                set available_qty = available_qty - 1
                where id = ${db.escape(bookId)};
            `)

            res.redirect('/adminDashboard/issue-requests')
        } else if (action == 'reject') {
            await execSql(`
                delete from requests
                where id = ${db.escape(id)};
            `)
            res.redirect('/adminDashboard/issue-requests');
        }
    } else {

        let issueReq = await execSql(`
            select requests.id , users.username, books.book_name
            from requests
            join books on requests.book_id = books.id
            join users on requests.user_id = users.id
            where requests.status = 'request-issue' and available_qty>=1;
        `);

        data = {
            username: req.user.name,
            state: 'issue-req',
            req: issueReq
        }

        res.render('adminDashboard', data);
    }
})


app.get('/adminDashboard/return-requests/:action?/:id?', validateJWT, async (req, res) => {
    let { action, id } = req.params;
    if (action && id) {
        if (action == 'accept') {
            let bookId = await execSql(`select r.book_id from requests r where r.id = ${db.escape(id)}`);
            await execSql(`
                delete from requests
                where id = ${db.escape(id)};
            `)
            bookId = bookId[0].book_id;
            await execSql(`
                update books
                set available_qty = available_qty + 1
                where id = ${db.escape(bookId)};
            `)

            res.redirect('/adminDashboard/issue-requests')
        } else if (action == 'reject') {
            await execSql(`
                update requests set status = 'issued' 
                where id = ${db.escape(id)};
            `)
            res.redirect('/adminDashboard/issue-requests');
        }
    } else {

        let issueReq = await execSql(`
            select requests.id , users.username, books.book_name
            from requests
            join books on requests.book_id = books.id
            join users on requests.user_id = users.id
            where requests.status = 'request-return';
        `);

        data = {
            username: req.user.name,
            state: 'return-req',
            req: issueReq
        }

        res.render('adminDashboard', data);
    }
})


app.get('/logout', validateJWT, (req, res) => {
    res.clearCookie('access-token');
    res.redirect('/');
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
                            else {
                                res.clearCookie('access-token');
                                res.redirect('/login?registered=true')
                            };
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
            if (result.length == 0) res.render('login', data = { error: "User doesn't exist" })
            else {
                let passMatch = await matchPass(password, result[0].salt, result[0].hash);
                if (passMatch) {
                    let user = { id: result[0].id, name: username, admin: result[0].admin };
                    const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET);
                    res.cookie("access-token", accessToken, {
                        maxAge: 90000000
                    });
                    if (user.admin) res.redirect('/adminDashboard');
                    else res.redirect('/userDashboard');
                }
                else res.render('login', data = { error: "Incorrect username or password" });
            }
        }
    )
})


app.listen(PORT, () => {
    console.log(`The server is running on http://localhost:${PORT}`)
});