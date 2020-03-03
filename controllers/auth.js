const express = require('express');
const router = express.Router();
const passport = require('passport');
var User = require('../models/user');

router.get('/success',
    passport.authenticate('session'),
    async function (req, res) {
        if (!req.user) {
            return res.status(403).end('Authentication failed');
        }

        // Assign guestId
        if (req.session.guestid) {
            let user = await User.findOne({
                _id: req.user.id
            });
            if (!user) {
                return res.status(404).end('Not found');
            }

            user.guestId = req.session.guestid;
            await user.save();
        }

        res.redirect('/profile');
    });

// Google
router.get('/google',
    passport.authenticate('google', {
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    }));

router.get('/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/auth/success');
    });

// Facebook
router.get('/facebook', passport.authenticate('facebook', {
    scope: ['email']
}));

router.get('/facebook/callback',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/auth/success');
    });

module.exports = router;