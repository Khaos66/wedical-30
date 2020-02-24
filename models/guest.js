const debug = require('debug')('wedical:guest');
const path = require('path');
const extend = require('extend');
const { Model, Timestamps } = require('nedb-models');
const ModelSanitizer = require('../extension/model-sanitizer');

/**
 * Model for party guests
 *
 * Properties:
 * - name
 * - email
 * - phone
 * - group
 * - address
 * - gender
 * - age
 * - expected
 * - state
 * - allergy
 * - diet
 */
class Guest extends Model {
    /**
     * defines the configuration of the datastore for this model
     * @return {Object}
     */
    static datastore() {
        debug('create guest datastore');
        return {
            filename: path.join(
                __dirname,
                '../data/guests.db'),
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
                phone: '',
                group: '',
                address: '',
                gender: '',
                age: '',
                expected: 'unsure',
                state: '',
                allergy: [],
                diet: [],
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
}

Guest.use(Timestamps);
Guest.use(ModelSanitizer);

// all possible genders
Guest.genders = { 'undefined': 'Undefined', 'm': 'Male', 'd': 'Diverse', 'f': 'Female' };

// all possible ages
Guest.ages = { 'undefined': 'Undefined', 'baby': 'Baby', 'child': 'Child', 'teen': 'Teen', 'youndAdult': 'Young Adult', 'adult': 'Adult', 'senior': 'Senoir' };

// all possible expectations
Guest.expectations = { 'expected': 'Will sure come', 'unsure': 'Might come', 'unexpected': 'Might not come' };

// all possible states
Guest.states = { 'invited': 'Invited', 'absent': 'Absent', 'attending': 'Attending' };

module.exports = Guest;