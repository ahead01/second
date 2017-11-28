var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var expressValidator = require('express-validator');
var index = require('./routes/index');
var auth = require('./routes/auth');
var mongoose = require('mongoose');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var flash = require('connect-flash');


// ENV variables
//var dotenv = require('dotenv').config();

// Authorization pkgs
var session =  require('express-session');
const MongoStore = require('connect-mongo')(session);

var app = express();
var mongoDBStore = process.env.MONGODB || 'mongodb://127.0.0.1/austin-dase';
/* Session configuration */
var sessionConfig = {
    secret: 'play hard',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 },
    store : new MongoStore({url: mongoDBStore})
};
if (app.get('env') === 'production') {
    app.set('trust proxy', 1) // trust first proxy
    sess.cookie.secure = true // serve secure cookies
}

/* view engine setup */
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
/* Not sure about this - got it from express-session
    app.set('trust proxy', 1) // trust first proxy
*/

/* Middleware */
// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressValidator());
app.use(cookieParser());
// Use the session middleware
app.use(session(sessionConfig));

app.use(passport.initialize());
app.use(flash());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

app.use(function(req, res, next){
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

app.use('/', index);
app.use('/auth', auth);




// catch 404 and forward to error handler
app.use(function(req, res, next) {
    console.log(req)
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
    console.log(err);
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error');
});




module.exports = app;
