require('dotenv').config();
const mongodb = require('./database/mongodb/db');
const userQuery = require('./database/mongodb/query'); 

mongodb.connectDB();

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const PORT = 3000;

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const verifyToken = require('./middlewares/jwt');
const { initializePassport, authenticatePassportJwt } = require('./middlewares/passport-jwt');

app.use(initializePassport());

let users = [];

app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true }));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.get('/users', (req, res) => {
  userQuery.getUsers().then((users) => {
    res.json(users);
  });
});

app.post('/users', (req, res) => {
  const user = req.body; 
  console.log(req);
  userQuery.createUser(user).then((user) => {
    res.status(201).json(user); 
  })
});
  
app.put('/users/:id', (req, res) => {
  const { id } = req.params; 
  const user = req.body; 
  userQuery.updateUser(id, user).then((user) => {
    res.status(200).json(user); 
  });
});

app.delete('/users/:id', (req, res) => {
  const { id } = req.params; 
  userQuery.deleteUser(id).then(() => {
    res.status(204).send(); 
  });
});

app.get('/users/search', (req, res) => {
    const { name } = req.query; 
    if (!name) {
      return res.status(400).send({ message: "Name query parameter is required" });
    }
    userQuery.findByName(name).then((users) => {
      res.status(200).json(users);
    });    
});

app.post("/user/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const payload = { email, password };
    const token = await login(payload);
    res.status(200).json({ message: "Success login!", token });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
});

async function login(payload) {
  try {
    const checkUser = await userQuery.findOneByEmail(payload.email);
    if (!checkUser) {
      throw new Error('Invalid email or password');
    }
    const user = {
      userId: checkUser.user_id,
      email: checkUser.email,
      password: checkUser.password
    };
    const isValidPassword = bcrypt.compareSync(payload.password, user.password);
    if (!isValidPassword) {
      throw new Error('Invalid email or password');
    }
    const key = process.env.JWT_SECRET || 'default_secret_key';
    const token = jwt.sign(user, key, { expiresIn: '30m' });
    return token;
  } catch (error) {
    console.error('Error login: ', error);
    throw error;
  }
}

app.get('/orders', verifyToken, (req, res) => {
  userQuery.getOrders().then((orders) => {
    res.json(orders);
  });
});

app.post('/orders', verifyToken, (req, res) => {
  const order = req.body; 
  userQuery.createOrder(order).then((order) => {
    res.status(201).json(order); 
  });
});

app.put('/orders/:id', (req, res) => {
  const { id } = req.params; 
  const order = req.body; 
  userQuery.updateOrder(id, order).then((order) => {
    res.status(200).json(order); 
  });
});

app.delete('/orders/:id', authenticatePassportJwt(), (req, res) => {
  const { id } = req.params; 
  userQuery.deleteOrder(id).then(() => {
    res.status(204).send(); 
  });
});

app.get('/orders/search', (req, res) => {
  const { status } = req.query; 

  if (!status) {
    return res.status(400).send({ message: "Status query parameter is required" });
  }
  userQuery.findByStatus(status).then((orders) => {
    res.status(200).json(orders); 
  });
});

app.get('/orders/:orderId', (req, res) => {
  const { orderId } = req.params; 
  userQuery.findOneByOrderId(orderId).then((order) => {
    res.status(200).json(order);
  });
});