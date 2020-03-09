const debug = require('debug')('wedical:login');
const express = require('express');
const router = express.Router();
const validator = require('express-validator');
const i18n = require('i18n');
const passport = require('passport');
const csrf = require('csurf');

// CSRF
var csrfProtection = csrf();

// Define the login page route.
router.get('/', csrfProtection, function (req, res) {
    debug('serve login page');

    // store redirect_url in session for redirect after social login
    req.session.redirect_url = req.query.redirect_url;

    res.render('login/login', {
        csrfToken: req.csrfToken()
    });
});

// Handle login POST
router.post('/',
    csrfProtection,
    // Validate input
    validator.body('email', i18n.__('not a valid email.')).isEmail(),
    validator.body('password', i18n.__('has to be at least 5 characters long.')).isLength({
        min: 4
    }),
    function (req, res, next) {
        debug('Got login POST. Redirect to: ' + encodeURIComponent(req.body.redirect_url));
        // Check for validation errors
        const errors = validator.validationResult(req);
        if (!errors.isEmpty()) {
            debug('validation errors: ' + errors.array());
            req.flash('error', errors.array());
            return res.redirect('/login?redirect_url=' + encodeURIComponent(req.body.redirect_url));
        }

        passport.authenticate('local', {
            failureFlash: true
        }, function (err, user, info) {
            // Handle authenticate result
            debug('authentication. info: ' + JSON.stringify(info));
            // Error
            if (err) {
                debug('failed with err: ' + JSON.stringify(err));
                return next(err);
            }

            // No user!
            if (!user) {
                debug('failed without user');
                req.flash('error', info);
                return res.redirect('/login?redirect_url=' + encodeURIComponent(req.body.redirect_url));
            }

            // Login valid => login user
            req.logIn(user, function (err) {
                // Error while login
                if (err) {
                    debug('login failed with err: ' + JSON.stringify(err));
                    return next(err);
                }

                debug('login successfull');
                // Redirect to page
                return res.redirect(req.body.redirect_url);
            });
        })(req, res, next);
    });

module.exports = router;