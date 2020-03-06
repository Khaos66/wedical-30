const debug = require('debug')('wedical:invite');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const {
    check,
    validationResult
} = require('express-validator');
var Invite = require('../models/invite');
var Guest = require('../models/guest');
var User = require('../models/user');
var Role = require('../models/role');
const sendmail = require('../mailer');

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
        email: value
    });
    // Unkown email, or email of same user
    let valid = !user || user._id == req.params.id;
    if (!valid) {
        throw new Error('Email is already in use');
    }
}

/**
 * Checks if a role name is already taken
 * @param {any} value
 * @param {Object} param1
 */
async function checkTokenExists(value, {
    req
}) {
    value = value.trim();
    let invite = await Invite.findOne({
        token: value
    });
    if (!invite) {
        throw new Error('No invite with this token found');
    }
}

async function findInviteGuest(req) {
    if (!req.params.token || !req.params.uid) {
        return null;
    }

    let invite = await Invite.findOne({
        token: req.params.token
    });
    if (!invite || invite.guests.indexOf(req.params.uid) < 0) {
        return null;
    }

    var guest = await Guest.findOne({
        _id: req.params.uid
    });
    if (!guest) {
        return null;
    }

    return {
        invite: invite,
        guest: guest
    };
}

// Define the invite code page route.
router.get('/', csrfProtection, function (req, res) {
    res.render('invite/code.pug', {
        csrfToken: req.csrfToken(),
        bodyClass: 'invite invite-code',
    });
});


// Define the invite register page route.
router.get('/:token/register/:utoken', csrfProtection, async function (req, res) {
    if (!req.params.token || !req.params.utoken) {
        return result.status(404).end();
    }

    let invite = await Invite.findOne({
        token: req.params.token
    });
    if (!invite) {
        return result.status(404).end();
    }

    var guest = await Guest.findOne({
        token: req.params.utoken
    });
    if (!guest || invite.guests.indexOf(guest._id) < 0) {
        return result.status(404).end();
    }

    req.session.guestid = guest._id;
    // For redirect after social login
    req.session.redirect_url = '/profile';

    res.render('invite/register.pug', {
        csrfToken: req.csrfToken(),
        guest: guest,
        bodyClass: 'invite invite-code',
    });
});


// Define the invite register page route.
router.post('/:token/register/:utoken',
    csrfProtection,
    check('password').notEmpty(),
    check('password2').custom((value, {
        req
    }) => value === req.body.password).withMessage('Passwords don\'t match'),
    check('email').isEmail().bail().custom(checkEmailExists),
    async function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({
                errors: errors.array()
            });
        }

        if (!req.params.token || !req.params.utoken) {
            return result.status(404).end();
        }

        let invite = await Invite.findOne({
            token: req.params.token
        });
        if (!invite) {
            return result.status(404).end();
        }

        var guest = await Guest.findOne({
            token: req.params.utoken
        });
        if (!guest || invite.guests.indexOf(guest._id) < 0) {
            return result.status(404).end();
        }

        // Create new user
        let user = await User.create({
            guestId: guest._id,
            name: guest.name,
            email: req.body[`email`],
            roles: [await Role.findOne({
                name: 'Guest'
            })]
        });

        // set password
        user.setLocalPw(req.body[`password`]);
        await user.save();

        // login as the new user
        req.login(user, function (err) {
            if (err) {
                return next(err);
            }
            return res.json({
                redirect: '/profile'
            });
        });
    });


// Define the invite code form route.
router.post('/',
    csrfProtection,
    check('token').notEmpty().bail().custom(checkTokenExists),
    function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            debug(`invite form error: ${errors}`);
            return res.redirect('/invite');
        }
        return res.redirect(`/invite/${req.body.token}`);
    });

// Define the invite page route.
router.get('/:token', csrfProtection, async function (req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({
        token: req.params.token
    });
    if (!invite) {
        return res.redirect('/invite');
    }
    if (!['open', 'accepted', 'declined'].indexOf(invite.state) < 0) {
        return res.redirect('/invite');
    }

    let guests = await Guest.find({
        _id: {
            $in: invite.guests
        }
    });

    res.render(`invite/${invite.state}.pug`, {
        bodyClass: 'invite',
        csrfToken: req.csrfToken(),
        invite: invite,
        guests: guests.map(guest => invite.addInviteLink(guest)),
    });
});


// Define the decline invite route.
router.get('/:token/decline', csrfProtection, async function (req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({
        token: req.params.token
    });
    if (!invite) {
        return res.redirect('/invite');
    }

    await invite.decline();

    return res.redirect(`/invite/${req.params.token}`);
});

// Define the accept invite route.
router.get('/:token/accept', csrfProtection, async function (req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({
        token: req.params.token
    });
    if (!invite) {
        return res.redirect('/invite');
    }

    await invite.accept();

    return res.redirect(`/invite/${req.params.token}`);
});

// Define the change guest state route.
router.post('/:token/gstate/:uid', csrfProtection, async function (req, res) {
    let result = await findInviteGuest(req);
    if (!result || req.body.value === undefined) {
        return result.status(404).end();
    }

    if (req.body.value === 'true') {
        result.guest.state = 'attending';
    } else {
        result.guest.state = 'absent';
    }

    await result.guest.save();

    return res.status(200).end('ok');
});

// Define the get guest diet/allergies route.
router.get('/:token/gdiet/:uid', csrfProtection, async function (req, res) {
    let result = await findInviteGuest(req);
    if (!result) {
        return result.status(404).end();
    }

    var pojo = result.guest.toPOJO();
    pojo.allergy = pojo.allergy || [];
    pojo.diet = pojo.diet || [];

    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
        data: {
            allergy: pojo.allergy,
            diet: pojo.diet
        }
    }));
});

// Define the put guest diet/allergies route.
router.put('/:token/gdiet/:uid', csrfProtection, async function (req, res) {
    let result = await findInviteGuest(req);
    if (!result || req.body.allergy1 === undefined || req.body.diet1 === undefined) {
        return result.status(404).end();
    }

    result.guest.allergy = [];
    result.guest.diet = [];

    for (var field in req.body) {
        if (typeof (req.body[field]) !== 'string' || !req.body[field]) {
            continue;
        }
        if (field.startsWith('allergy')) {
            result.guest.allergy.push(req.body[field]);
        } else if (field.startsWith('diet')) {
            result.guest.diet.push(req.body[field]);
        }
    }

    await result.guest.save();

    return res.status(200).end('ok');
});

// Define the get guest invite link route.
router.get('/:token/ginvite/:uid', csrfProtection, async function (req, res) {
    let result = await findInviteGuest(req);
    if (!result) {
        return result.status(404).end();
    }

    result.invite.addInviteLink(result.guest);

    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
        data: {
            inviteLink: result.guest.inviteLink
        }
    }));
});

// Define the get guest invite link route.
router.post('/:token/ginvite/:uid', csrfProtection, async function (req, res) {
    let result = await findInviteGuest(req);
    if (!result || !req.body.mail) {
        return result.status(404).end();
    }

    result.guest.email = req.body.mail;
    await result.guest.save();

    result.invite.addInviteLink(result.guest);

    sendmail(req, req.body.mail, 'guest_invite', {
        guest: result.guest
    });

    return res.end();
});


module.exports = router;