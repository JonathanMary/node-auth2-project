const router = require("express").Router()
const { checkUsernameExists, validateRoleName } = require('./auth-middleware')
const { jwtSecret } = require("../secrets") // use this secret!
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const Users = require("../users/users-model")

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
  */
  const credentials = req.body

  const salt = bcrypt.genSaltSync(10)
  const hash = bcrypt.hashSync(credentials.password, salt)

  credentials.username = credentials.username.trim()
  credentials.role_name = credentials.role_name.trim()
  credentials.password = hash

  Users.add(credentials)
       .then(created => {
         const [newUser] = created
         res.status(201).json(newUser)
       })
       .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body

  Users.findBy({ username: username })
       .then(([user]) => {
         if (user && bcrypt.compareSync(password, user.password)) {
           const token = buildToken(user)
           res.status(200).json({
             message: `${username} is back!`, token
            })
         } else { // FOR SOME REASON TEST 2 DOESN'T WORK WITHOUT THIS
           res.status(401).json({ message: "Invalid credentials" })
         }
       })
       .catch(next)
});

const buildToken = user => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const config = {
    expiresIn: "1d",
  }
  return jwt.sign(payload, jwtSecret, config)
}

router.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message,
    stack: err.stack,
    custom: 'Error in auth-router.js',
  })
})

module.exports = router;
