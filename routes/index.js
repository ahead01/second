var express = require('express');
var router = express.Router();

function authenticationMiddleware () {
    return function(req, res, next) {

        console.log('req.session.passport' + req.session.passport);
        console.log('req.session' + req.session);

        if (req.isAuthenticated()) return next();
        res.redirect('auth/sign-in');
    }
}

/* GET home page. */
router.get('/', function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('index', { title: 'Austin Dase' });
});

/* GET home page. */
router.get('/profile', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('user/profile', { title: 'Profile' });
});

/* GET home page. */
router.get('/profile/google', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('user/google-profile', { title: 'Google Profile' });
});


module.exports = router;
