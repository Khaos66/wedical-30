const debug = require('debug')('wedical:manage-guests');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const { check, validationResult } = require('express-validator');
const reqSanitizer = require('../../extension/request-sanitizer');
const { Auth } = require('../../auth');
const { addBreadcrump } = require('../../utils');
var Guest = require('../../models/guest');

// CSRF
var csrfProtection = csrf();

async function getGuest(req, res) {
    if (req.params.id) {
        debug(`Get guest with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let guest = await Guest.findOne({ _id: req.params.id });
        if (guest) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ data: guest.toPOJO() }));
        } else {
            debug('ERROR: Guest not found!');
        }
    } else {
        debug('ERROR: Called GET without ID');
    }
    res.status(404).end('not found');
}

async function addGuests(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    for (let key of Object.keys(req.body)) {
        if (!key.startsWith('guest') || !key.endsWith('name')) {
            continue;
        }
        let index = parseInt(key.substr(5, key.length - 9));
        if (index === NaN) {
            continue;
        }
        let name = req.body[`guest${index}name`].trim();
        if (name) {
            debug(`Add guest: ${name}`);
            await Guest.create({
                name: name,
                age: req.body[`guest${index}age`],
                gender: req.body[`guest${index}gender`],
                expected: req.body[`guest${index}expected`],
                group: req.body.group,
                address: req.body.address,
            });
        }
    }
    res.setHeader('CSRF-Token', req.csrfToken());
    res.status(200).end('ok');
}

async function delGuest(req, res) {
    if (req.params.id) {
        debug(`Deleting guest with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let guest = await Guest.findOne({ _id: req.params.id });
        if (guest) {
            await guest.remove();
            return res.status(200).end('ok');
        } else {
            debug('ERROR: Guest not found!');
        }
    } else {
        debug('ERROR: Called DELETE without ID');
    }
    res.status(404).end('not found');
}

async function putGuest(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    if (req.params.id) {
        debug(`Put guest with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let guest = await Guest.findOne({ _id: req.params.id });
        if (guest) {
            guest.assign(req.body);
            await guest.save();
            return res.status(200).end('ok');
        } else {
            debug('ERROR: Guest not found!');
        }
    } else {
        debug('ERROR: Called PUT without ID');
    }
    res.status(404).end('not found');
}

async function listGuests(req, res) {
    res.setHeader('CSRF-Token', req.csrfToken());
    res.setHeader('Content-Type', 'application/json');
    let guests = await Guest.find();
    res.end(JSON.stringify({ data: guests.map(g => g.toPOJO()) }));
}

// Define the guests page route.
router.get('/',
    csrfProtection,
    Auth.authenticate('/manage/guests'),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    addBreadcrump('Guest List', '/manage/guests'),
    function(req, res) {
        res.render('manage/guests', { 
            csrfToken: req.csrfToken(),
            genders: Guest.genders,
            ages: Guest.ages,
            expectations: Guest.expectations, 
        });
    });

// /list feeds DataTable in client with data
router.get('/list',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    listGuests);

// Add guests
router.post('/',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    addGuests
);

// Remove guest
router.delete('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    delGuest
);

// Get guest
router.get('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    getGuest
);

// Save guest
router.put('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'guests' }),
    reqSanitizer.removeBody(['_id', 'createdAt', 'updatedAt']),
    check('name').notEmpty(),
    putGuest
);

module.exports = router;