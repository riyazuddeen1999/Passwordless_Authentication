const express = require('express');
const router = express.Router();

router.get('/ping', (req, res) => {
  console.log('✅ /ping hit');
  res.status(200).json({ message: 'pong' });
});

module.exports = router;



//const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');

//const router = express.Router();

router.get('/ping', (req, res) => {
  console.log('✅ GET /ping hit');
  res.status(200).json({ message: 'pong' });
});


// Register
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).send('User already exists');

    const user = new User({ username, password });
    await user.save();

    res.status(201).send('User registered successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering user');
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send('Invalid credentials');

    res.send('Login successful');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

module.exports = router;
