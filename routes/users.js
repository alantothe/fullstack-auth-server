const express = require("express");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const { db, mongoConnect } = require("../mongo");
const jwt = require('jsonwebtoken');

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // generate salt and hash password
    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user object with unique ID
    const user = {
      id: uuid(),
      email: email,
      password: passwordHash,
    };

    // insert user into database
    await mongoConnect();
    const result = await db().collection("users").insertOne(user);

    // send success response
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An error occurred" });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // find user with matching email in the database
    const user = await db().collection('users').findOne({ email });

    // if user is not found
    if (!user) {
      res.json({ success: false, message: 'Could not find user.' }).status(204);
      return;
    }

    // compare the password with the hashed password
    const match = await bcrypt.compare(password, user.password);

    // if passwords do not match
    if (!match) {
      res.json({ success: false, message: 'Password was incorrect.' }).status(204);
      return;
    }

    // checks for codeimmersives email
    const userType = email.includes('codeimmersives.com') ? 'admin' : 'user';

    // create user data
    const userData = {
      date: new Date(),
      userId: user.id,
      scope: userType,
    };


    const exp = Math.floor(Date.now() / 1000) + 60 * 60;
    const payload = {
      userData,
      exp,
    };

    // create jwt with key
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, jwtSecretKey);






    res.json({ success: true, token, email });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});


module.exports = router;



