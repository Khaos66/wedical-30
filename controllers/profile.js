const debug = require('debug')('wedical:profile');
const express = require('express');
const router = express.Router();
const {
    Auth
} = require('../auth');
const csrf = require('csurf');
var User = require('../models/user');
var Guest = require('../models/guest');

// CSRF
var csrfProtection = csrf();

// Define the profile page route.
router.get('/',
    Auth.authenticate('/profile'),
    csrfProtection,
    async function(req, res) {
        let user = await User.findOne({ _id: req.user.identity._id });
        let guest = await Guest.findOne({ _id: user.guestId });
        res.render('profile', {
            csrfToken: req.csrfToken(),
            guest: guest
        });
    });

module.exports = router;