const debug = require('debug')('wedical:manage-roles');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const { check, validationResult } = require('express-validator');
const reqSanitizer = require('../../extension/request-sanitizer');
const customUtils = require('nedb/lib/customUtils');
const { Auth } = require('../../auth');
const { addBreadcrump, base64PNG } = require('../../utils');
var QRcode = require('../../models/qrcode');
var Invite = require('../../models/invite');

// CSRF
var csrfProtection = csrf();

async function removeLogo(req, res) {
    let qrcode = await QRcode.findOne();
    if (qrcode) {
        qrcode.logo = '';
        await qrcode.save();
    }
    return res.redirect('/manage/qrcode');
}

async function saveQR(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    debug('Save QR code');
    let qrcode = await QRcode.findOne();
    if (qrcode) {
        // logo file
        if (req.files && req.files.logo) {
            qrcode.logo = await base64PNG(req.files.logo.data);
        }
        qrcode.assign(req.body);
        await qrcode.save();
        return res.redirect('/manage/qrcode');
    } else {
        debug('ERROR: Invite not found!');
    }
    res.status(404).end('not found');
}


// Define the roles page route
router.get('/',
    csrfProtection,
    Auth.authenticate('/manage/qrcode'),
    Auth.authorize('manage', { 'Segment': 'qrcode' }),
    addBreadcrump('QR Code', '/manage/qrcode'),
    async function(req, res) {
        let qrcode = await QRcode.singelton();

        // Generare random invitation QR code
        let imgQr = await qrcode.getImageSource(Invite.inviteUrl(customUtils.uid(6)), true);

        res.render('manage/qrcode', {
            csrfToken: req.csrfToken(),
            errorLevels: QRcode.errorLevels,
            qrcode: qrcode,
            qrsource: imgQr.img,
            qrerr: imgQr.err,
        });
    });

// Save QR code config
router.post('/',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'qrcode' }),
    reqSanitizer.removeBody(['_csrf']),
    check('version').custom((value, { req }) => value >= 1 && value <= 40),
    check('errorCorrection').isIn(['L', 'M', 'Q', 'H']),
    check('logoSize').custom((value, { req }) => value >= 0 && value <= 100),
    saveQR
);

// Define the roles page route
router.get('/dellogo',
    csrfProtection,
    Auth.authenticate('/manage/qrcode'),
    Auth.authorize('manage', { 'Segment': 'qrcode' }),
    removeLogo
);

module.exports = router;