require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const { body, validationResult } = require("express-validator");
const path = require("path");

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            maxAge: 1000 * 60 * 60
        }
    })
);

app.use(express.static("public"));

const db = new sqlite3.Database("database.db");

db.run(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
email TEXT UNIQUE,
password TEXT
)
`);

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect("/login");
}

app.get("/", (req, res) => {
    res.redirect("/login");
});

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "views/register.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "views/login.html"));
});

app.get("/dashboard", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "views/dashboard.html"));
});

app.post(
    "/register", [
        body("username").trim().isLength({ min: 3 }),
        body("email").isEmail(),
        body("password").isLength({ min: 6 })
    ],
    async(req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.send("Validation Failed");
        }

        const { username, email, password } = req.body;

        try {
            const hashedPassword = await bcrypt.hash(password, 12);

            db.run(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)", [username, email, hashedPassword],
                function(err) {
                    if (err) {
                        return res.send("User already exists");
                    }

                    res.redirect("/login");
                }
            );
        } catch {
            res.send("Error");
        }
    }
);

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE email=?", [email],
        async(err, user) => {
            if (!user) {
                return res.send("Invalid Credentials");
            }

            const match = await bcrypt.compare(
                password,
                user.password
            );

            if (!match) {
                return res.send("Invalid Credentials");
            }

            req.session.userId = user.id;
            req.session.username = user.username;

            res.redirect("/dashboard");
        }
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login");
    });
});

app.listen(process.env.PORT, () => {
    console.log(
        `Server running on http://localhost:${process.env.PORT}`
    );
});