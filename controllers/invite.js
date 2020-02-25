const debug = require('debug')('wedical:invite');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const { check, validationResult } = require('express-validator');
var Invite = require('../models/invite');
var Guest = require('../models/guest');

// CSRF
var csrfProtection = csrf();

/**
 * Checks if a role name is already taken
 * @param {any} value
 * @param {Object} param1
 */
async function checkTokenExists(value, { req }) {
    value = value.trim();
    let invite = await Invite.findOne({ token: value });
    if (!invite) {
        throw new Error('No invite with this token found');
    }
}

// Define the invite code page route.
router.get('/', csrfProtection, function(req, res) {
    res.render('invite/code.pug', {
        csrfToken: req.csrfToken(),
        bodyClass: 'invite invite-code',
    });
});

// Define the invite code form route.
router.post('/',
    csrfProtection,
    check('token').notEmpty().bail().custom(checkTokenExists),
    function(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            debug(`invite form error: ${errors}`);
            return res.redirect('/invite');
        }
        return res.redirect(`/invite/${req.body.token}`);
    });

// Define the invite page route.
router.get('/:token', csrfProtection, async function(req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.redirect('/invite');
    }
    if (!['open', 'accepted', 'declined'].indexOf(invite.state) < 0) {
        return res.redirect('/invite');
    }

    let guests = await Guest.find({ _id: { $in: invite.guests } });

    res.render(`invite/${invite.state}.pug`, {
        bodyClass: 'invite',
        csrfToken: req.csrfToken(),
        invite: invite,
        guests: guests.map(guest => invite.addInviteLink(guest)),
    });
});


// Define the decline invite route.
router.get('/:token/decline', csrfProtection, async function(req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.redirect('/invite');
    }

    await invite.decline();

    return res.redirect(`/invite/${req.params.token}`);
});

// Define the accept invite route.
router.get('/:token/accept', csrfProtection, async function(req, res) {
    if (!req.params.token) {
        return res.redirect('/invite');
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.redirect('/invite');
    }

    await invite.accept();

    return res.redirect(`/invite/${req.params.token}`);
});

// Define the change guest state route.
router.post('/:token/gstate/:uid', csrfProtection, async function(req, res) {
    if (!req.params.token || !req.params.uid || req.body.value === undefined) {
        return res.status(404).end();
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.status(404).end();
    }

    if (invite.guests.indexOf(req.params.uid) < 0) {
        return res.status(404).end();
    }

    var guest = await Guest.findOne({ _id: req.params.uid });
    if (!guest) {
        return res.status(404).end();
    }

    if (req.body.value === 'true') {
        guest.state = 'attending';
    } else {
        guest.state = 'absent';
    }

    await guest.save();

    return res.status(200).end('ok');
});

// Define the get guest diet/allergies route.
router.get('/:token/gdiet/:uid', csrfProtection, async function(req, res) {
    if (!req.params.token || !req.params.uid) {
        return res.status(404).end();
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.status(404).end();
    }

    if (invite.guests.indexOf(req.params.uid) < 0) {
        return res.status(404).end();
    }

    var guest = await Guest.findOne({ _id: req.params.uid });
    if (!guest) {
        return res.status(404).end();
    }

    var pojo = guest.toPOJO();
    pojo.allergy = pojo.allergy || [];
    pojo.diet = pojo.diet || [];

    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ data: { allergy: pojo.allergy, diet: pojo.diet } }));
});

// Define the put guest diet/allergies route.
router.put('/:token/gdiet/:uid', csrfProtection, async function(req, res) {
    if (!req.params.token || !req.params.uid || req.body.allergy1 === undefined || req.body.diet1 === undefined) {
        return res.status(404).end();
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.status(404).end();
    }

    if (invite.guests.indexOf(req.params.uid) < 0) {
        return res.status(404).end();
    }

    var guest = await Guest.findOne({ _id: req.params.uid });
    if (!guest) {
        return res.status(404).end();
    }

    guest.allergy = [];
    guest.diet = [];

    for (var field in req.body) {
        if (typeof(req.body[field]) !== 'string' || !req.body[field]) {
            continue;
        }
        if (field.startsWith('allergy')) {
            guest.allergy.push(req.body[field]);
        } else if (field.startsWith('diet')) {
            guest.diet.push(req.body[field]);
        }
    }

    await guest.save();

    return res.status(200).end('ok');
});

// Define the get guest invite link route.
router.get('/:token/ginvite/:uid', csrfProtection, async function(req, res) {
    if (!req.params.token || !req.params.uid) {
        return res.status(404).end();
    }

    let invite = await Invite.findOne({ token: req.params.token });
    if (!invite) {
        return res.status(404).end();
    }

    if (invite.guests.indexOf(req.params.uid) < 0) {
        return res.status(404).end();
    }

    var guest = await Guest.findOne({ _id: req.params.uid });
    if (!guest) {
        return res.status(404).end();
    }

    invite.addInviteLink(guest);

    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ data: { inviteLink: guest.inviteLink } }));
});

module.exports = router;