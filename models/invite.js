const debug = require('debug')('wedical:invite');
const path = require('path');
const extend = require('extend');
const { Model, Timestamps } = require('nedb-models');
const ModelSanitizer = require('../extension/model-sanitizer');
const customUtils = require('nedb/lib/customUtils');
const config = require('../config');
const QRcode = require('./qrcode');
var Guest = require('./guest');

/**
 * Model for invitations
 *
 * Properties:
 * - title
 * - type (guestlist, wildcard)
 * - guests
 * - tickets
 * - token
 * - state (open, declined, accepted)
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
                state: 'open',
                guests: [],
                type: 'guestlist',
                tickets: 0,
                token: customUtils.uid(6)
            },
        });
    }

    /**
     * Declines an invite for all guests
     */
    async decline() {
        this.state = 'declined';
        for(var guestId of this.guests) {
            var guest = await Guest.findOne({_id: guestId});
            if (guest != null) {
                guest.attendance = 'absent';
                await guest.save();
            }
        }
        await this.save();
    }

    /**
     * Accepts an invite for all guests
     */
    async accept() {
        this.state = 'accepted';
        for(var guestId of this.guests) {
            var guest = await Guest.findOne({_id: guestId});
            if (guest != null) {
                guest.attendance = 'attending';
                await guest.save();
            }
        }
        await this.save();
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

// all possible invite types
Invite.types = { 'guestlist': 'Guest with an invite', 'wildcard': 'Tickets'};

// all possible invite states
Invite.states = { 'open': 'Open', 'accepted': 'Accepted', 'declined': 'Declined'};


module.exports = Invite;