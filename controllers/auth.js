const express = require('express');
const router = express.Router();
const passport = require('passport');
var User = require('../models/user');
var Role = require('../models/role');
var Guest = require('../models/guest');
const {
    Strategies
} = require('../auth-utils');
const {
    Auth
} = require('../auth');

// Google
router.get('/google/callback', function (req, res, next) {
    passport.authenticate('google', async function (err, user, info) {
        if (err) {
            return next(err);
        }

        let guestid = req.session.guestid;
        req.session.guestid = '';
        let redirect_url = req.session.redirect_url || '/profile';
        req.session.redirect_url = '';

        if (!user) {
            if (req.session.auth_action == 'register' && info && guestid) {
                let guestRole = await Role.findOne({
                    name: 'Guest'
                });
                user = await User.create({
                    googleId: info.id,
                    guestId: guestid,
                    strategy: Strategies.GOOGLE,
                    name: info.displayName,
                    email: info.emails[0].value,
                    picture: info.photos.length > 0 ? info.photos[0].value : '',
                    roles: [guestRole._id]
                });

                // Aquire auth profile from user roles
                await Auth.compileAuthorization(user);

                // assign email
                let guest = await Guest.findOne({
                    _id: guestid
                });
                guest.email = user.email;
                guest.userId = user._id;
                await guest.save();
            } else {
                req.flash('error', {
                    param: 'Auth',
                    msg: res.__('You don\'t seem to be invited')
                });
                return res.redirect('/login?redirect_url=' + encodeURIComponent(redirect_url));
            }
        }

        req.logIn(user, function (err) {
            if (err) {
                return next(err);
            }
            return res.redirect(redirect_url);
        });
    })(req, res, next);
});

router.get('/google/:action',
    function (req, res, next) {
        if (!req.params.action) {
            req.session.auth_action = '';
            return res.redirect('/login');
        }
        req.session.auth_action = req.params.action;
        next();
    },
    passport.authenticate('google', {
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    }));


// Facebook
router.get('/facebook/callback', function (req, res, next) {
    passport.authenticate('facebook', async function (err, user, info) {
        if (err) {
            return next(err);
        }

        let guestid = req.session.guestid;
        req.session.guestid = '';
        let redirect_url = req.session.redirect_url || '/profile';
        req.session.redirect_url = '';

        if (!user) {
            if (req.session.auth_action == 'register' && info && guestid) {
                let guestRole = await Role.findOne({
                    name: 'Guest'
                });
                user = await User.create({
                    facebookId: info.id,
                    guestId: guestid,
                    strategy: Strategies.FACEBOOK,
                    name: `${info.name.givenName} ${info.name.familyName}`,
                    email: info.emails[0].value,
                    picture: info.photos.length > 0 ? info.photos[0].value : '',
                    roles: [guestRole._id]
                });

                // Aquire auth profile from user roles
                await Auth.compileAuthorization(user);

                // assign email
                let guest = await Guest.findOne({
                    _id: guestid
                });
                guest.email = user.email;
                guest.userId = user._id;
                await guest.save();
            } else {
                req.flash('error', {
                    param: 'Auth',
                    msg: res.__('You don\'t seem to be invited')
                });
                return res.redirect('/login?redirect_url=' + encodeURIComponent(redirect_url));
            }
        }

        req.logIn(user, function (err) {
            if (err) {
                return next(err);
            }
            return res.redirect(redirect_url);
        });
    })(req, res, next);
});

router.get('/facebook/:action',
    function (req, res, next) {
        if (!req.params.action) {
            req.session.auth_action = '';
            return res.redirect('/login');
        }
        req.session.auth_action = req.params.action;
        next();
    }, passport.authenticate('facebook', {
        scope: ['email']
    }));

module.exports = router;