const { JWT_SECRET } = require("../secrets"); 
const jwt = require('jsonwebtoken')
const { findBy } = require("../users/users-model")

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({ status: 401, message: `Token required` })
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      next({ status: 401, message: `'Token invalid'` })
    } else {
      req.decoded = decoded
      next()
    }
  })

}

const only = role_name => (req, res, next) => {
  if (role_name === req.decoded.role_name) {
    next()
  } else {
    res.status(403).json({
      message: 'This is not for you'
    })
  }
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await findBy({ username: req.body.username })
    if (!user) {
      next({ status: 401, message: `Invalid credentials` })
    } else {
      req.user = user
      next()
    }
  } catch (err) {
    next(err)
  }
}


const validateRoleName = (req, res, next) => {

  if (!req.body.role_name || req.body.role_name.trim()) {
    req.role_name = 'student'
    next()
  }
  else if (req.body.role_name.trim() === 'admin') {
    next({ status: 422, message: 'Role name can not be admin' })
  }
  else if (req.body.role_name.trim().length > 32) {
    next({ status: 422, message: 'Role name can not be longer than 32 chars' })
  }
  else {
    req.role_name = req.body.role_name.trim()
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
