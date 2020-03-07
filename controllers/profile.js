const debug = require('debug')('wedical:profile');
const express = require('express');
const router = express.Router();
const {
    Auth
} = require('../auth');
const csrf = require('csurf');

// CSRF
var csrfProtection = csrf();

// Define the profile page route.
router.get('/',
    Auth.authenticate('/profile'),
    csrfProtection,
    function (req, res) {
        res.render('profile', {
            csrfToken: req.csrfToken()
        });
    });

module.exports = router;