const express = require("express");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const { db, mongoConnect } = require("../mongo");

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

module.exports = router;



