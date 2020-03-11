const express = require('express');
const router = express.Router();
const passport = require('passport');
var User = require('../models/user');
var Guest = require('../models/guest');

const handleLogin = async function (req, res) {
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
    let redirect_url = req.session.redirect_url || '/profile';
    req.session.redirect_url = '';

    if (!guestid) {
        if (!user.guestId) {
            req.logout();
            await user.remove();

            req.flash('error', {
                param: 'Auth',
                msg: 'You don\'t seem to be invited'
            });
            return res.redirect('/login?redirect_url=' + encodeURIComponent(redirect_url));
        }
    } else {
        // Assign guestId
        user.guestId = guestid;
        await user.save();

        // assign email
        let guest = await Guest.findOne({
            _id: guestid
        });
        guest.email = user.email;
        guest.userId = user._id;
        await guest.save();
    }

    return res.redirect(redirect_url);
};

// Google
router.get('/google',
    passport.authenticate('google', {
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    }));

router.get('/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    handleLogin);

// Facebook
router.get('/facebook', passport.authenticate('facebook', {
    scope: ['email']
}));

router.get('/facebook/callback',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    handleLogin);

module.exports = router;