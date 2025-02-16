const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
require("dotenv").config();
const bcrypt = require("bcrypt");

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(passport.initialize());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.get("/", async (req, res, next) => {
  try {
    const { rows: usermessages } = await pool.query(
      `SELECT messages.*, users.first_name, users.last_name 
      FROM messages 
      join users on messages.user_id = users.id
      `
    );
    res.render("index", { user: req.user, messages: usermessages });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.get("/sign-in", (req, res) => res.render("sign-in-form"));

app.post("/sign-in", async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [req.body.username]
    );
    const user = rows[0];
    if (user) {
      // User already exists
      return res.status(400).send("User with this username already exists.");
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query(
      "insert into users (first_name, last_name, username, password) values ($1, $2, $3, $4)",
      [req.body.firstname, req.body.lastname, req.body.username, hashedPassword]
    );
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.redirect("/sign-in");

      req.logIn(user, (err) => {
        if (err) return next(err);
        return res.redirect("/");
      });
    })(req, res, next);
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.get("/join-club", (req, res) => res.render("join-the-club"));

app.post("/join-club", async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).send("You must be logged in to join the club.");
    }
    if (req.body.secretpassword == process.env.SECRET_PASS) {
      await pool.query(
        "UPDATE users SET membership_status = TRUE where username = $1",
        [req.user.username]
      );
      return res.redirect("/");
    } else {
      return res.status(400).send("Incorrect secret password.");
    }
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.get("/log-in", (req, res) => res.render("log-in-form"));

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/log-in",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/post-message", (req, res) => res.render("post-message"));

app.post("/post-message", async (req, res, next) => {
  try {
    await pool.query(
      "INSERT INTO messages (user_id, title, timestamp, text) VALUES ($1, $2, $3, $4)",
      [req.user.id, req.body.title, new Date(), req.body.message]
    );
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post("/delete-message", async (req, res, next) => {
  try {
    await pool.query(
      "DELETE FROM messages where id = $1 ",
      [req.body.message_id]
    );
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.listen(3000, () => console.log("app listening on port 3000!"));
