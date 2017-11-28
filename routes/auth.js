var express = require('express');
var router = express.Router();
const db_conn = require('../db');
const User = require('../models/user-model');
var dpost = require('debug')('austin-dase:POST:');
var dget = require('debug')('austin-dase:GET:');
var dreq = require('debug')('austin-dase:req:');
var dinfo = require('debug')('austin-dase:info:');
var expressValidator = require('express-validator');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
//var FacebookStrategy = require('passport-facebook').Strategy;
var flash = require('connect-flash');
const bcrypt = require('bcrypt-nodejs');

function authenticationMiddleware () {
    return function(req, res, next) {

        console.log('req.session.passport' + req.session.passport);
        console.log('req.session' + req.session);

        if (req.isAuthenticated()) return next();
        res.redirect('auth/sign-in');
    }
}
/* passport config
*
* createStrategy is special - look it up
* *
//passport.use(User.createStrategy());
//passport.use(new LocalStrategy(User.authenticate()));
//passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
*/

passport.use(new LocalStrategy(
    function(username, password, done) {
        console.log(username);
        console.log(password);
        User.findOne({ username: username }, function (err, user) {
            if (err) { return done(err); }
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }else
                {
                    if (!user.password) {
                        return done(null, false, {message: 'Incorrect password.'});
                    }else{
                        const hash = user.password.toString();
                        console.log(hash);
                        bcrypt.compare(password, hash, function (err, res) {
                            if (res === true) {
                                return done(null, user);
                            } else {
                                return done(null, false, {message: 'Incorrect password.'});
                            }
                        });
                    }
                }
        });
    }
));


passport.serializeUser(function(user, done) {
    done(null, user);
    // done(null, user.id);
});

passport.deserializeUser(function(user, done) {
    User.find({username: user.username}, function(err, user) {
        done(err, user);
    });
});




/**/
/* base url = /auth */

/* debug function */

function debugErr(err, res, req){
    console.log(req.body);
    console.log(err);
    res.render('error', {title: "Error", error: err, req: req});
};

/* GET users listing. */
router.get('/sign-in', function(req, res, next) {
    dget('/sign-in');
  res.render('auth/sign-in', {title: 'Sign In', info:{}});
});


router.get('/sign-out', authenticationMiddleware(), function(req, res) {
    console.log('signing out');
    req.logout();
    req.session.destroy(function(){
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

router.post('/sign-in', passport.authenticate('local',
                                                {
                                                    successRedirect: '/profile',
                                                    failureRedirect: '/auth/sign-in'
                                                }
                                            ));
/*router.post('/sign-in', function(req, res, next) {
    dpost('/sign-in');
    dinfo("New Usr: ");
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('password', 'Password cannot be blank').notEmpty();
    req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });
    const errors = req.validationErrors();
    if (errors) {
        req.flash('errors', errors);
        console.log('errors: ');
        console.log(errors);
        return res.render('auth/sign-in', {info: errors});
    }





    passport.authenticate('local', function(err, user, info) {
        console.log("authenticating");
        if (err) { return next(err); }
        if (!user) {
            return res.redirect('auth/sign-in' + {info: {errors:err}});
        }
        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            return res.redirect('/profile' + user.username);
        });
    })(req, res, next);

/!*    var NewUser = new User(req.body) ;
    dinfo(NewUser);
    dinfo("Logging in");
    req.logIn(NewUser, function(err) {
        if (err) {
            console.log(err);
            return res.render('auth/sign-in',
                {
                    title: 'Sign In - Error',
                    errors: err,
                    user: NewUser
                }
            );
        }
        dinfo("Successful authentication");
    });*!/
console.log("Somethings wrong with passport authentiacte");
    res.redirect('/profile');
    //res.render('/profile', {title: 'Profile', info:{}});
});*/

/* Moving from sign-in to sign-up */
router.post('/sign-up', function(req, res, next) {
    dpost('/sign-up');
    dreq(req.body);



    var email = req.body.email ;
    dinfo("Rendering sign-up page with: " + email);
    res.render('auth/sign-up', { info : {email: email}, title: 'Sign Up'} );

});

//* Actually signing up */
router.post('/sign-up/new', function(req, res, next) {
    dpost('/sign-up/new');

    /*
    * Validate request
    *  Don't think i need to do this because of mongoose schema
    *
    *
    req.checkBody('userName', 'User Name cannot be blank!').notEmpty();
    const errors = req.validationErrors();
    if(errors){
        console.log(errors);
        //res.render('auth/sign-up', {title: 'Sign Up - Error', errors: errors} );

    }
    */
    /* End manual validation */
    dinfo("New Usr: ");
    var NewUser = new User(req.body) ;
    dinfo("Got here 1");
    dinfo(NewUser);
    dinfo("Got here 2");

    User.findOne({ username: NewUser.username }, function (err, existingUser) {
        if (err) {
            consloe.log(err);
            if (existingUser) {
                req.flash('errors', {msg: 'Account with that email address already exists.'});
            }
            return res.render('auth/sign-up',
                {
                    title: 'Sign Up - Error',
                    errors: err,
                    user: NewUser
                }
            );
        }
        console.log("Saving");
        NewUser.save(function(err) {
            if (err) {
                console.log(err);
                return res.render('auth/sign-up',
                    {
                        title: 'Sign Up - Error',
                        errors: err,
                        user: NewUser
                    }
                );
            }
            console.log("Logging in");
            req.logIn(NewUser, function(err) {
                if (err) {
                    console.log(err);
                    return res.render('auth/sign-up',
                        {
                            title: 'Sign Up - Error',
                            errors: err,
                            user: NewUser
                        }
                    );
                 }
                console.log("Successful authentication");
                console.log(req.user);
                console.log(req.isAuthenticated());
                res.locals.isAuthenticated = req.isAuthenticated();
                res.render('user/profile', {title: 'Profile', info:{}});
/*                res.render('auth/sign-in',
                    {
                        title: 'Sign In - Signed Up Successfully',
                        info: {
                            email: NewUser.email,
                            userName: NewUser.userName
                        }
                    }
                );*/
            });
        });
    });
/*
    User.register(NewUser, req.body.password, function(err){
        if(err){
            dinfo("register error - " + err);
            //debugErr(err, res, req);
            res.render('auth/sign-up',
                {
                    title: 'Sign Up - Error',
                    errors: err
                }
            );
            return(null);
        }
        // Saved in db successfully
        dinfo("Registered " + NewUser.userName);
        dinfo("Authenticating... ");

        User.authenticate('username', 'password', function(err, result){
            if(err){
                res.render('auth/sign-up',
                    {
                        title: 'Sign Up - Error',
                        errors: err
                    });
                return;
            }
            if(result){
                console.log("Successful authentication");
                console.log(result);
                res.render('auth/sign-in',
                    {
                        title: 'Sign In - Signed Up Successfully',
                        info: {
                            email: NewUser.email,
                            userName: NewUser.userName
                        }
                    }
                );
            }else{
                console.log("Problem authenticating");
                console.log(result);
                return;
            }
        });

    });
*/
});



module.exports = router;
