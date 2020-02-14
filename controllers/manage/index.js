const express = require('express');
const router = express.Router();
const { Auth } = require('../../auth');
const { addBreadcrump } = require('../../utils');
const dataExt = require('../../extension/data-ext');
var Guest = require('../../models/guest');
var User = require('../../models/user');
var Invite = require('../../models/invite');

// Manage bread crump
var breadcrump = addBreadcrump('Manage', '/manage');

// Define the manage page route
router.get('/',
    Auth.authenticate('/manage'),
    Auth.authorize('manage', {}),
    breadcrump,
    async function(req, res) {
        let allGuests = await Guest.find();
        let genders = dataExt.countBy(allGuests, (g) => g.gender, Object.keys(Guest.genders));
        let ages = dataExt.countBy(allGuests, (g) => g.age, Object.keys(Guest.ages));
        let expectations = dataExt.countBy(allGuests, (g) => g.expected, Object.keys(Guest.expectations));

        let allInvites = await Invite.find();
        let invites = dataExt.countBy(allInvites, (g) => g.type, ['guestlist', 'wildcard'], (g) => g.type === 'guestlist' ? g.guests.length : g.tickets);

        res.render('manage/index', {
            guestCount: allGuests.length,
            guestGenders: genders,
            guestAges: ages,
            guestsExpected: expectations,
            inviteCount: allInvites.length,
            inviteSum: dataExt.sum(invites),
            invites: invites,
            userCount: await User.count(),
        });
    });
/*
 * Setup sub-page routes
 * (auth is handled inside!)
 */
// manage guests routes
router.use('/guests', breadcrump, require('./guests'));

// manage invites routes
router.use('/invites', breadcrump, require('./invites'));

// manage users & routes routes
router.use('/users', breadcrump, require('./users'));
router.use('/roles', breadcrump, require('./roles'));

module.exports = router;