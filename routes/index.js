var express = require('express');
var router = express.Router();
var path = require('path');

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
router.get('/profile/google', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('user/google-profile', { title: 'Google Profile' });
});

/* GET home page. */
router.get('/tic-tac-toe', authenticationMiddleware(), function(req, res, next) {
    //console.log(req.user);
    //console.log(req.isAuthenticated());
    res.render('projects/tic-tac-toe');
});

/* GET home page. */
router.get('/pizza-shop', authenticationMiddleware(), function(req, res, next) {
    //console.log(req.user);
    //console.log(req.isAuthenticated());
    //res.render('projects/dase-pizza-w-cart');
    res.sendFile(path.join(__dirname, '..', 'views/projects/dase-pizza-w-cart.html'));
});


/* GET remove profile. */
router.get('/profile/remove', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());

    res.redirect('/auth/profile/remove');
    //res.render('user/google-profile', { title: 'Google Profile' });
});


/* GET update profile page. */
router.get('/profile/update', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.redirect('/auth/profile');
    //res.render('/', { title: 'Google Profile' });
});

/* GET remove profile. */
router.get('/about', authenticationMiddleware(), function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());

    res.render('about');
    //res.render('user/google-profile', { title: 'Google Profile' });
});

module.exports = router;
