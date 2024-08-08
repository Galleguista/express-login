const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { expressjwt: jwtMiddleware } = require('express-jwt');
require('dotenv').config();

const sequelize = require('./config/database');
const User = require('./models/User'); 

const app = express();
app.use(bodyParser.json());
sequelize.sync().then(() => {
  console.log('Database & tables created!');
});

app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await User.create({ username, password: hashedPassword, email });
    res.status(201).json({ message: 'User created', user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/protected', jwtMiddleware({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }), (req, res) => {
  res.json({ message: 'This is a protected route', user: req.auth });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
