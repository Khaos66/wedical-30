const debug = require('debug')('wedical:qrcode');
const path = require('path');
const extend = require('extend');
const { Model, Timestamps } = require('nedb-models');
const ModelSanitizer = require('../extension/model-sanitizer');
const QRCode = require('qrcode');
const config = require('../config');
const { addQRLogo, readQRCode } = require('../utils');


class QRcode extends Model {
    /**
     * defines the configuration of the datastore for this model
     * @return {Object}
     */
    static datastore() {
        debug('create guest datastore');
        return {
            filename: path.join(
                __dirname,
                '../data/qrcode.db'),
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
                version: 3,
                errorCorrection: 'M',
                logo: '',
                logoSize: 15,
            },
        });
    }

    /**
     * Sanitize model data before storing them
     */
    sanitize() {
        this.version = parseInt(this.version);
        this.logoSize = parseInt(this.logoSize);
    }

    /**
     * Generates a QR code as Base64 image source
     * @param {string} code Security code of initation
     */
    async getImageSource(code) {
        let baseUrl = config.baseUrl;
        if (!baseUrl.endsWith('/')) {
            baseUrl += '/';
        }
        let url = `${baseUrl}invite/${code}`;
        let imgSrc = '';
        let error = '';
        try {
            imgSrc = await QRCode.toDataURL(url, {
                errorCorrectionLevel: this.errorCorrection,
                version: this.version,
            });
            if (this.logo) {
                // Place logo over QR code
                imgSrc = await addQRLogo(imgSrc, this.logo, this.logoSize);

                // Check if QR code is still readable
                await readQRCode(imgSrc);
            }
        } catch (ex) {
            error = ex.message ? ex.message : ex;
        }
        return { img: imgSrc, err: error };
    }
}

QRcode.use(Timestamps);
QRcode.use(ModelSanitizer);

QRcode.errorLevels = { 'L': 'Low (7%)', 'M': 'Medium (15%)', 'Q': 'Quartile (25%)', 'H': 'High (30%)' };

module.exports = QRcode;