const debug = require('debug')('wedical:invite');
const path = require('path');
const extend = require('extend');
const { Model, Timestamps } = require('nedb-models');
const ModelSanitizer = require('../extension/model-sanitizer');
const customUtils = require('nedb/lib/customUtils');
const config = require('../config');
const QRcode = require('./qrcode');

/**
 * Model for invitations
 *
 * Properties:
 * - title
 * - type (guestlist/wildcard)
 * - guests
 * - tickets
 * - token
 */
class Invite extends Model {
    /**
     * defines the configuration of the datastore for this model
     * @return {Object}
     */
    static datastore() {
        debug('create invite datastore');
        return {
            filename: path.join(
                __dirname,
                '../data/invites.db'),
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
                title: '',
                guests: [],
                type: 'guestlist',
                tickets: 0,
                token: customUtils.uid(6)
            },
        });
    }

    /**
     * Sanitize model data before storing them
     */
    sanitize() {
        this.title = this.title.trim();
        if (this.type != 'wildcard') {
            this.tickets = 0;
        }
        if (this.type != 'guestlist') {
            this.guests = [];
        } else if (!Array.isArray(this.guests)) {
            this.guests = [this.guests];
        }
    }

    /**
     * Returns the URL a guest has to use to accept the invitation
     */
    getInviteUrl() {
        return Invite.inviteUrl(this.token);
    }

    /**
     * Returns the URL a guest has to use to accept the invitation
     * @param {string} code Invitation security token
     */
    static inviteUrl(code) {
        let baseUrl = config.baseUrl;
        if (!baseUrl.endsWith('/')) {
            baseUrl += '/';
        }
        return `${baseUrl}invite/${code}`;
    }

    /**
     * Generates a QR code as Base64 image source
     */
    async getQRCode() {
        let qrcode = await QRcode.singelton();
        return await qrcode.getImageSource(Invite.inviteUrl(this.token));
    }
}

Invite.ensureIndex({ fieldName: 'token', unique: true });

Invite.use(Timestamps);
Invite.use(ModelSanitizer);

module.exports = Invite;