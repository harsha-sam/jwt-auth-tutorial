var express = require('express');
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
require('dotenv').config()// will config the .env file present in the directory


let POSTS = [
  {
    username: "Harsha",
    title: "Post 1",
    body: "1234"
  },
  {
    username: "Harsha",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "Harsha",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "Sm",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "no",
    title: "Post 2",
    body: "1234"
  },
]

let DB = []

// used to store refresh tokens, as we will manually expire them
let SESSIONS = []

const generateAccessToken = (user) => {
  // jwt will make sure to expire this token in 30 seconds
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    'expiresIn': '30s'
  })
}

const PORT = process.env.APP_PORT || "8081";
const app = express();
app.use(express.json())

// middlewares
const validateToken = async (token, tokenSecret) => {
  // returns user info, if the jwt token is valid
  return await jwt.verify(token, tokenSecret,
    (error, payload) => {
      if (error) {
        throw (error)
      }
      return payload
    })
}
const validateAccessToken = async (req, res, next) => {
  // returns user info, if the jwt token is valid
  try {
    req.user = await validateToken(req.body['accessToken'], process.env.ACCESS_TOKEN_SECRET)
    next();
  }
  catch (error) {
    res.status(401).
      json({ error: error.message || 'Invalid access token' })
  }
}

const validateRefreshToken = async (req, res, next) => {
  try {
    req.user = await validateToken(req.body['refreshToken'], process.env.REFRESH_TOKEN_SECRET)
    next();
  }
  catch (error) {
    res.status(401).
      json({ error: error.message || 'Invalid refresh token' })
  }
}


app.get("/posts", validateAccessToken, (req, res) => {
  const { username } = req.user;
  const userPosts = POSTS.filter((post) => post.username === username)
  res.json(userPosts)
})

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  let hash = "";
  const salt = await bcrypt.genSalt(12);
  hash = await bcrypt.hash(password, salt);
  DB.push({ username, passwordHash: hash })
  console.log(DB);
  res.json("Successfully registered")
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  for (let user of DB) {
    // authentication
    if (user.username === username && await bcrypt.compare(password, user.passwordHash)) {
      // sending an accesstoken and refresh token in response
      // refresh token won't have expiration date and 
      // it will be used to generate new access token

      // We will store refresh token in db and it'll expire when the user logs out
      const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, {
        'expiresIn': '30s'
      })
      const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET)
      SESSIONS.push(refreshToken);
      res.json({ accessToken, refreshToken });
    }
  }
})

app.post('/token', validateRefreshToken, (req, res) => {
  // generating new access token, once the refresh token is valid and exists in db
  const { username } = req.user;
  if (SESSIONS.includes(req.body['refreshToken'])) {
    res.json({ accessToken: generateAccessToken({ username }) })
  }
  else {
    res.status(403).json('Forbidden: refresh token is expired')
  }
})

app.delete("/logout", async (req, res) => {
  // deleting refresh token from db 
  SESSIONS = SESSIONS.filter((session) => session != req.body['refreshToken']);
  res.sendStatus(204);
})

app.get('/', (req, res) => {
  res.send("Hello !")
})
app.listen(PORT, () => {
  console.log("Listening on port", PORT);
})