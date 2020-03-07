var express = require('express');
var router = express.Router();

// load invite route
router.use('/invite', require('./invite'));

// load management routes
router.use('/manage', require('./manage'));

// load login/logout route
router.use('/login', require('./login'));
router.use('/logout', require('./logout'));
router.use('/auth', require('./auth'));

router.use('/profile', require('./profile'));

// Define the home page route.
router.get('/', function (req, res) {
    res.render('index', {
        bodyClass: 'startpage',
    });
});

module.exports = router;