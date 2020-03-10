const express = require('express');
const router = express.Router();
const passport = require('passport');
var User = require('../models/user');
var Guest = require('../models/guest');

router.get('/success',
    passport.authenticate('session'),
    async function (req, res) {
        if (!req.user) {
            return res.status(403).end('Authentication failed');
        }

        // Find user
        let user = await User.findOne({
            _id: req.user.id
        });
        if (!user) {
            return res.status(404).end('Not found');
        }

        // Check if invited. Else delete.
        let guestid = req.session.guestid;
        req.session.guestid = '';

        let log = 'guestid: ' + guestid;

        if (!guestid) {
            if (!user.guestId) {
                req.logout();
                await user.remove();
                return res.status(403).end('You don\'t seem to be invited!');
            }
        } else {
            log += '. Upd User';

            // Assign guestId
            user.guestId = guestid;
            await user.save();

            log += '. Upd Guest';
            // assign email
            let guest = await Guest.findOne({
                _id: guestid
            });
            guest.email = user.email;
            await guest.save();
        }


        return res.end(log);
        let redirect_url = req.session.redirect_url || '/profile';
        return res.redirect(redirect_url);
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
        res.redirect('/auth2/success');
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
        res.redirect('/auth2/success');
    });

module.exports = router;