const debug = require('debug')('wedical:profile');
const express = require('express');
const fs = require('fs');
const {
    Image
} = require('image-js');
const router = express.Router();
const {
    Auth
} = require('../auth');
const csrf = require('csurf');
const {
    check,
    validationResult
} = require('express-validator');
const customUtils = require('nedb/lib/customUtils');
var User = require('../models/user');
var Guest = require('../models/guest');

// CSRF
var csrfProtection = csrf();

/**
 * Checks if a email is already taken
 * @param {any} value
 * @param {Object} param1
 */
async function checkEmailExists(value, {
    req
}) {
    value = value.trim().toLowerCase();
    let user = await User.findOne({
        email: value,
        $not: {
            _id: req.user.identity._id
        }
    });
    // Unkown email
    let valid = !user
    if (!valid) {
        throw new Error('Email is already in use');
    }
}

// Define the profile page route.
router.get('/',
    Auth.authenticate('/profile'),
    csrfProtection,
    async function (req, res) {
        let user = await User.findOne({
            _id: req.user.identity._id
        });
        let guest = await Guest.findOne({
            _id: user.guestId
        });
        res.render('profile', {
            csrfToken: req.csrfToken(),
            guest: guest,
            identity: user
        });
    });

// Define the save profile route
router.post('/',
    Auth.authenticate('/profile'),
    csrfProtection,
    check('email').isEmail().bail().custom(checkEmailExists),
    async function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({
                errors: errors.array()
            });
        }

        let user = await User.findOne({
            _id: req.user.identity._id
        });
        let guest = await Guest.findOne({
            _id: user.guestId
        });

        if (user.email !== req.body.email) {
            user.email = req.body.email;
            await user.save();
        }

        guest.email = req.body.email;
        guest.phone = req.body.phone;
        guest.allergy = [];
        guest.diet = [];

        for (var field in req.body) {
            if (typeof (req.body[field]) !== 'string' || !req.body[field]) {
                continue;
            }
            if (field.startsWith('allergy')) {
                guest.allergy.push(req.body[field]);
            } else if (field.startsWith('diet')) {
                guest.diet.push(req.body[field]);
            }
        }

        await guest.save();

        res.json({
            redirect: '/profile'
        });
    });

// Define the save avatar route
router.post('/avatar',
    Auth.authenticate('/profile'),
    csrfProtection,
    async function (req, res) {
        // store file
        if (req.files.avatar) {
            const folder = './public';
            const avatarUrl = '/img/avatars/';
            // Find new filename
            let filepath = customUtils.uid(15) + '.png';
            while (fs.existsSync(folder + avatarUrl + filepath)) {
                filepath = customUtils.uid(15) + '.png';
            }

            let user = await User.findOne({
                _id: req.user.identity._id
            });
            let cleanFile = user.picture;

            // load image and resize
            let img = await Image.load(req.files.avatar.data);
            // Cut out square
            if (img.width != img.height) {
                let shortEdge = Math.min(img.width, img.height);
                img = img.crop({
                    width: shortEdge,
                    height: shortEdge,
                    x: Math.floor((img.width - shortEdge) / 2),
                    y: Math.floor((img.height - shortEdge) / 2),
                });
            }
            // Resize to save storage
            if (img.width > 200) {
                img = img.resize({
                    width: 200
                });
            }

            // save image
            await img.save(folder + avatarUrl + filepath, {
                format: 'png'
            });

            // update user
            user.picture = avatarUrl + filepath;
            await user.save();

            // cleanup old image
            if (cleanFile && fs.existsSync(folder + cleanFile)) {
                fs.unlinkSync(folder + cleanFile);
            }
        }

        res.redirect('/profile');
    });
module.exports = router;