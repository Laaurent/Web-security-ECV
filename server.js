
const express = require('express')
const mustacheExpress = require('mustache-express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const cookieSession = require('cookie-session')
const flash = require('connect-flash')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const sqlite3 = require('sqlite3').verbose()

const app = express()
const port = 3000

app.engine('mustache', mustacheExpress())
app.set('view engine', 'mustache')
app.set('views', __dirname + '/views')

app.use(cookieParser())
app.use(cookieSession({
  name: 'session',
  keys: ['cats'],
  maxAge: 24 * 60 * 60 * 1000
}))
app.use(flash())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(passport.initialize())
app.use(passport.session())

const users = [
  { username: 'marty', password: 'i-love-hoverboards', email: 'marty.mcfly@hill-valley.com' },
  { username: 'doc', password: 'einstein', email: 'mad-scientisty@hill-valley.com' }
]

const guests = [{ name: 'Madonna'}, { name: 'Luke Skywalker' }]

const db = new sqlite3.Database(':memory:')
db.serialize(() => {
  db.run('CREATE TABLE users (id integer primary key, username varchar(255), email varchar(255), password varchar(1024))')
  users.forEach(({ username, email, password }) => {
    db.run(`INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`)
  })

  db.run('CREATE TABLE guests (id integer primary key, name varchar(20))')
  guests.forEach(({ name }) => {
    db.run(`INSERT INTO guests (name) VALUES ('${name}')`)
  })
})

passport.use(new LocalStrategy(
  (username, password, done) => {
    console.log(`Looking for user ${username}`)
    db.get(`SELECT id, username, email, password FROM users WHERE username = '${username}'`, (error, user) => {
      console.log(`Found him: ${JSON.stringify(user)}`)
      if (error) {
        console.log('Error')
        return done(error)
      }

      if (!user) {
        console.log('User does not exist')
        return done(null, false)
      }

      if (password !== user.password) {
        console.log('Password is wrong')
        return done(null, false)
      }

      const { id, username, email } = user
      console.log(`Authenticating user ${username}`)
      return done(null, { id, username, email })
    })
  }
))

passport.serializeUser((user, done) => {
  done(null, user)
})

passport.deserializeUser((user, done) => {
  return done(null, user)
})

const isConnected = req => req.session.passport && req.session.passport.user

const redirectIfAnonymous = (req, res, next) => {
  if (isConnected(req)) {
    next()
  } else {
    res.redirect('/login')
  }
}

const redirectIfConnect = (req, res, next) => {
  if (isConnected(req)) {
    res.redirect('/')
  } else {
    next()
  }
}

app.get('/', redirectIfAnonymous, (req, res) => {
  const { user } = req.session.passport
  const welcomeMessage = req.query.welcome ? req.query.welcome : 'Welcome to the party !'

  db.all('SELECT name FROM guests', (err, rows) => {
    res.render('guest-list.mustache', { user, welcomeMessage, guests: rows.map(({ name }) => name) })
  })
})

app.get('/logout', (req, res) => {
  req.session = null
  res.redirect('/login')
})

app.get('/login', redirectIfConnect, (req, res) => {
  console.log('/login')
  res.render('login.mustache', { flash: req.flash('error') } )
})

app.post('/login',
  (req, res, next) => {
    console.log(`Trying to authenticate with following credentials: ${req.body.username} ${req.body.password}`)
    next()
  },
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  })
)

app.post('/invite', (req, res) => {
  db.exec(`INSERT INTO guests (name) VALUES ('${req.body.guest}')`)
  res.redirect('/')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})