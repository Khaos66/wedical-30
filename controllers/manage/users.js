const debug = require('debug')('wedical:manage-users');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const { check, validationResult } = require('express-validator');
const reqSanitizer = require('../../extension/request-sanitizer');
const { Auth } = require('../../auth');
const { addBreadcrump } = require('../../utils');
var Role = require('../../models/role');
var User = require('../../models/user');

// CSRF
var csrfProtection = csrf();

/**
 * Checks if a email is already taken
 * @param {any} value
 * @param {Object} param1
 */
async function checkEmailExists(value, { req }) {
    value = value.trim().toLowerCase();
    let user = await User.findOne({ email: value });
    // Unkown email, or email of same user
    let valid = !user || user._id == req.params.id;
    if (!valid) {
        throw new Error('Email is already in use');
    }
}

async function getUser(req, res) {
    if (req.params.id) {
        debug(`Get user with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let user = await User.findOne({ _id: req.params.id });
        if (user) {
            res.json({ data: user.toPOJO() });
        } else {
            debug('ERROR: User not found!');
        }
    } else {
        debug('ERROR: Called GET without ID');
    }
    res.status(404).end('not found');
}

async function addUser(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    // Create new user
    let user = await User.create({
        name: req.body[`name`],
        email: req.body[`email`]
    });

    // set password
    user.setLocalPw(req.body[`password`]);

    // Grant rights
    setRoles(user, req);
    await user.save();

    res.setHeader('CSRF-Token', req.csrfToken());
    res.status(200).end('ok');
}

function setRoles(user, req) {
    user.roles = [];
    for (var [key, value] of Object.entries(req.body)) {
        if (key.startsWith('r_') && value === 'on') {
            let parts = key.split('_');
            user.roles.push(parts[1]);
            // remove body field, so assign() can be used afterwards
            delete req.body[key];
        }
    }
}

async function putUser(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    if (req.params.id) {
        debug(`Put user with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let user = await User.findOne({ _id: req.params.id });
        if (user) {
            // Change authorization profile first
            setRoles(user, req);
            // New password?
            if (req.body.password) {
                user.setLocalPw(req.body.password);
            }
            delete req.body.password;
            delete req.body.password2;
            // Assign other fields
            user.assign(req.body);
            await user.save();
            return res.status(200).end('ok');
        } else {
            debug('ERROR: User not found!');
        }
    } else {
        debug('ERROR: Called PUT without ID');
    }
    res.status(404).end('not found');
}

async function delUser(req, res) {
    if (req.params.id) {
        debug(`Deleting user with id: ${req.params.id}`);
        res.setHeader('CSRF-Token', req.csrfToken());
        let user = await User.findOne({ _id: req.params.id });
        if (user) {
            await user.remove();
            return res.status(200).end('ok');
        } else {
            debug('ERROR: User not found!');
        }
    } else {
        debug('ERROR: Called DELETE without ID');
    }
    res.status(404).end('not found');
}

async function listUsers(req, res) {
    res.setHeader('CSRF-Token', req.csrfToken());
    let roles = await Role.dictionary('_id', 'name');
    let users = await User.find();
    res.json({
        data: users.map(g => {
            let obj = g.toPOJO();
            // Translate role id to name
            for (let index in obj.roles) {
                let roleId = obj.roles[index];
                if (roles[roleId]) {
                    obj.roles[index] = roles[roleId];
                } else {
                    delete obj.roles[index];
                }
            }
            return obj;
        })
    });
}

// Define the users page route
router.get('/',
    csrfProtection,
    Auth.authenticate('/manage/users'),
    Auth.authorize('manage', { 'Segment': 'users' }),
    addBreadcrump('Users', '/manage/users'),
    async function(req, res) {
        res.render('manage/users', {
            csrfToken: req.csrfToken(),
            roles: await Role.find(),
        });
    });

// /list feeds DataTable in client with data
router.get('/list',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'users' }),
    listUsers);

// Add user
router.post('/',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'users' }),
    check('name').notEmpty(),
    check('password').notEmpty(),
    check('password2').custom((value, { req }) => value === req.body.password).withMessage('Passwords don\'t match'),
    check('email').isEmail().bail().custom(checkEmailExists),
    addUser
);

// Remove user
router.delete('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'users' }),
    delUser
);

// Get user
router.get('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'users' }),
    getUser
);

// Save user
router.put('/:id',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'users' }),
    reqSanitizer.removeBody(['_id', 'createdAt', 'updatedAt']),
    check('name').notEmpty(),
    check('password2').if((value, { req }) => req.body.password).custom((value, { req }) => value === req.body.password).withMessage('Passwords don\'t match'),
    check('email').isEmail().bail().custom(checkEmailExists),
    putUser
);

module.exports = router;