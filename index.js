require('./utils.js');

require('dotenv').config();
const url = require('url');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const port = process.env.PORT || 3020;

const Joi = require('joi');

const expireTime = 60 * 60 * 1000 //1 hour (minutes * seconds * milliseconds)

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}))

app.use(express.static(__dirname + "/public"));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized" });
        return;
    }
    else {
        next();
    }
}

const navLinks = [
    { name: "Home", link: '/' },
    { name: "Vegetables", link: '/members' },
    { name: "Login", link: '/login' },
    { name: "Admin", link: '/admin' },
    { name: "404", link: '/404' }
]

app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.thisURL = url.parse(req.url).pathname;
    next();
})

app.get('/', (req, res) => {
    res.render('index', { loggedIn: req.session.authenticated ? true : false, name: req.session.name });
})

app.get('/about', (req, res) => {
    res.render("about");
})

app.get('/signup', (req, res) => {
    res.render('signup');
})

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        res.render("signupSubmit", {
            type: validationResult.error.details[0].type,
            name: name, email: email, password: password
        });
    } else {
        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });
        console.log("Inserted user");

        req.session.authenticated = true;
        req.session.name = name;
        req.session.user_type = 'user';
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
    }


})

app.get('/login', (req, res) => {
    res.render('login');
})

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);

        res.render("loginSubmit", { error: "invalid chars" });
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");

        res.render("loginSubmit", { error: "no user" });
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");

        res.render("loginSubmit", { error: "bad password" });
        return;
    }
})

app.use('/members', sessionValidation);
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var pics = ['/broccoli.jpg', '/carrot.jpg', '/pepper.jpg'];

    res.render("members", { name: req.session.name });
})

app.get('/logout', (req, res) => {
    req.session.destroy();

    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ name: 1, _id: 1, user_type: 1 }).toArray();

    console.log(result);
    res.render("admin", { users: result });
});

app.get('/admin/promote', async (req, res) => {
    var username = req.query.name;
    console.log(username);

    userCollection.updateOne({ name: username }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
})

app.get('/admin/demote', async (req, res) => {
    var username = req.query.name;

    userCollection.updateOne({ name: username }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
})

app.get('*', (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log('Node application listening on port ' + port);
})