const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const User = require('../users/users-model.js');
const { JWT_SECRET } = require("../secrets"); // use this secret!


router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username, password: hash, role_name })
    .then(newUser => {
      res.status(201).json(newUser);
    })
    .catch(next);
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = tokenBuilder(req.user);
    console.log(token)
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token
    });
  } else {
    next({ status: 401, message: 'Invalid Credentials' });
  }
});

function tokenBuilder(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(
    payload,
    JWT_SECRET,
    options
  )
}

module.exports = router;
