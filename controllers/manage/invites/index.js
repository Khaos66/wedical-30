const debug = require('debug')('wedical:manage-guests');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const {
    check,
    validationResult
} = require('express-validator');
const reqSanitizer = require('../../../extension/request-sanitizer');
const {
    Auth
} = require('../../../auth');
const {
    addBreadcrump
} = require('../../../utils');
var Invite = require('../../../models/invite');
var Guest = require('../../../models/guest');

// CSRF
var csrfProtection = csrf();

async function getInvite(req, res) {
    if (req.params.id) {
        debug(`Get invite with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let invite = await Invite.findOne({
            _id: req.params.id
        });
        if (invite) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                data: invite.toPOJO()
            }));
        } else {
            debug('ERROR: Invite not found!');
        }
    } else {
        debug('ERROR: Called GET without ID');
    }
    res.status(404).end('not found');
}

async function delInvite(req, res) {
    if (req.params.id) {
        debug(`Deleting invite with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let invite = await Invite.findOne({
            _id: req.params.id
        });
        if (invite) {
            await invite.remove();
            return res.status(200).end('ok');
        } else {
            debug('ERROR: Invite not found!');
        }
    } else {
        debug('ERROR: Called DELETE without ID');
    }
    res.status(404).end('not found');
}

async function addInvite(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            errors: errors.array()
        });
    }

    // Create new invite
    let invite = await Invite.create({
        title: req.body[`title`],
    });
    // Assign other fields
    invite.assign(req.body);
    await invite.save();

    // Change state of added guests
    for (var removeGuest of invite.guests) {
        var guest = await Guest.findOne({
            _id: removeGuest
        });
        if (!guest.state || guest.state === '') {
            guest.setAttending();
            await guest.save();
        }
    }

    res.setHeader('CSRF-Token', req.csrfToken());
    res.status(200).end('ok');
}

async function putInvite(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            errors: errors.array()
        });
    }

    if (req.params.id) {
        debug(`Put invite with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let invite = await Invite.findOne({
            _id: req.params.id
        });
        if (invite) {
            // Change state of removed guests
            for (var removeGuest of invite.guests) {
                if (!req.body.guests || req.body.guests.indexOf(removeGuest) < 0) {
                    var guest = await Guest.findOne({
                        _id: removeGuest
                    });
                    if (guest.state === 'invited') {
                        guest.state = '';
                        await guest.save();
                    }
                }
            }
            // Change state of added guests
            if (req.body.guests) {
                if (!Array.isArray(req.body.guests)) {
                    req.body.guests = [req.body.guests];
                }
                for (var addGuest of req.body.guests) {
                    if (invite.guests.indexOf(addGuest) < 0) {
                        var guest = await Guest.findOne({
                            _id: addGuest
                        });
                        if (guest.state === '') {
                            guest.state = 'invited';
                            await guest.save();
                        }
                    }
                }
            } else {
                // No more guests selected
                invite.guests = [];
            }

            // save new invite details
            invite.assign(req.body);
            await invite.save();

            return res.status(200).end('ok');
        } else {
            debug('ERROR: Invite not found!');
        }
    } else {
        debug('ERROR: Called PUT without ID');
    }
    res.status(404).end('not found');
}

async function listInvites(req, res) {
    res.setHeader('CSRF-Token', req.csrfToken());
    let invites = await Invite.find();
    res.json({
        data: invites.map(o => o.toPOJO())
    });
}

let breadcrump = addBreadcrump('Invites', '/manage/invites');

// print QR codes route
router.use('/qrprint', breadcrump, require('./qrprint'));

// Define the invites page route.
router.get('/',
    csrfProtection,
    Auth.authenticate('/manage/invites'),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    breadcrump,
    async function (req, res) {
        res.render('manage/invites/index', {
            csrfToken: req.csrfToken(),
            guests: await Guest.find(),
        });
    });

// /list feeds DataTable in client with data
router.get('/list',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    listInvites);

// Add invite
router.post('/',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    check('title').notEmpty(),
    check('type').notEmpty(),
    addInvite
);

// Remove invite
router.delete('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    delInvite
);

// Get invite
router.get('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    getInvite
);

// Save invite
router.put('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', {
        'Segment': 'invites'
    }),
    reqSanitizer.removeBody(['_id', 'createdAt', 'updatedAt']),
    check('title').notEmpty(),
    check('type').notEmpty(),
    putInvite
);

module.exports = router;