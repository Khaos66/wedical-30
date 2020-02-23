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

  let guests = await Guest.find({ _id: { $in: invite.guests }});
  
  res.render(`invite/${invite.state}.pug`, {
    bodyClass: 'invite',
    invite: invite,
    guests: guests,
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

module.exports = router;
