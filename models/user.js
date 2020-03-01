const debug = require('debug')('wedical:user');
const path = require('path');
const extend = require('extend');
const crypto = require('crypto');
const { Model, Timestamps } = require('nedb-models');
const { Strategies } = require('../auth-utils');
const ModelSanitizer = require('../extension/model-sanitizer');

/**
 * Model for website users
 *
 * Properties:
 * - name
 * - email
 * - strategy
 * - roles
 * - salt
 * - pwHash
 * - guestId
 * - picture
 *
 * - googleId (OAuth2 Google profile ID)
 */
class User extends Model {
    /**
     * defines the configuration of the datastore for this model
     * @return {Object}
     */
    static datastore() {
        debug('create user datastore');
        return {
            filename: path.join(
                __dirname,
                '../data/users.db'),
            inMemoryOnly: false,
        };
    }

    /**
     * Defines default values
     * @return {Object}
     */
    static defaults() {
        return extend(true, super.defaults(), {
            values: {
                name: '',
                email: '',
                strategy: Strategies.UNKNOWN,
                roles: [],
                guestId: '',
                picture: ''
            },
        });
    }

    /**
     * Sanitize model data before storing them
     */
    sanitize() {
        this.email = this.email.trim().toLowerCase();
        this.name = this.name.trim();
    }

    /**
     * Marks the user as local user account (not third party)
     * @param {string} password - password
     */
    setLocalPw(password) {
        this.strategy = Strategies.LOCAL;
        this.salt = crypto.randomBytes(16).toString('hex');
        this.pwHash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512')
            .toString('hex');
    }

    /**
     * Validates a user password
     * @param {string} password - password
     * @return {bool}
     */
    validatePassword(password) {
        const hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512')
            .toString('hex');
        return this.pwHash === hash;
    }
}

User.use(Timestamps);
User.use(ModelSanitizer);

module.exports = User;