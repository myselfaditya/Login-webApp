const router = require("express").Router();
const passport = require("passport");
const jwt = require('jsonwebtoken');
const db = require('../model/db');
const bcrypt = require('bcryptjs');

router.get("/login/success", (req, res) => {
	const { email, password } = req.body;

  // Check if email and password exist
  if (!email || !password) {
    return res.status(400).render("login", {
      message: 'Please provide email and password'
    });
  }

  // Check if user exists && password is correct
  db.start.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
    console.log(results);
    console.log(password);
    const isMatch = await bcrypt.compare(password, results[0].password);
    console.log(isMatch);
    if(!results || !isMatch ) {
      return res.status(401).render("login", {
        message: 'Incorrect email or password'
      });
    } else {
      //If everything ok, send token to client
      const id = results[0].id;
      console.log(id);
      const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
      });

      const cookieOptions = {
        expires: new Date(
          Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true
      };
      res.cookie('jwt', token, cookieOptions);

      res.status(200).redirect("/");
    }
  });});

  router.post('/register', (req, res) => {
	console.log(req.body);
  const { name, email, password, passwordConfirm } = req.body;

  // Check if user exists && password is correct
  db.start.query('SELECT email FROM users WHERE email = ?', [email], async (error, results) => {
    if(error) {
      console.log(error)
    }

    if(results.length > 0 ) {
      return res.render('register', {
                message: 'That Email has been taken'
              });
    } else if(password !== passwordConfirm) {
      return res.render('register', {
        message: 'Passwords do not match'
      });
    }
      
    let hashedPassword = await bcrypt.hash(password, 8);
    console.log(hashedPassword);

    db.start.query('INSERT INTO users SET ?', { name: name, email: email, password: hashedPassword }, (error, result) => {
      if(error) {
        console.log(error)
      } else {
        db.start.query('SELECT id FROM users WHERE email = ?', [email], (error, result) => {
          const id = result[0].id;
          console.log(id);
          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
          });

          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
            ),
            httpOnly: true
          };
          res.cookie('jwt', token, cookieOptions);

          res.status(201).redirect("/");
        });
      }
    });
  });})

router.get("/login/failed", (req, res) => {
	res.status(401).json({
		error: true,
		message: "Log in failure",
	});
});

router.get("/google", passport.authenticate("google", ["profile", "email"]));

router.get(
	"/google/callback",
	passport.authenticate("google", {
		successRedirect: process.env.CLIENT_URL,
		failureRedirect: "/login/failed",
	})
);

router.get("/logout", (req, res) => {
	req.logout();
	res.redirect(process.env.CLIENT_URL);
});

module.exports = router;
