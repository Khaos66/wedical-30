const { Image } = require('image-js');
const QrCode = require('qrcode-reader');

/**
 * Adds a breadcrump link to the page
 * @param {string} title Button title
 * @param {string} link Link to follow for the button
 */
const addBreadcrump = function(title, link) {
    return function(req, res, next) {
        res.locals.breadcrumps = res.locals.breadcrumps || [];
        res.locals.breadcrumps.push({
            title: title,
            link: link,
        });
        next();
    }
}

/**
 * Ensure that the data is PNG
 * @param {Array} data Image data
 */
const base64PNG = async function(data) {
    let image = await Image.load(data);
    return `data:image/png;base64,${image.toBase64('image/png')}`;
}

/**
 * Places a logo at the center of a QR code
 * @param {string} code Base64 Image string
 * @param {string} logo Base64 Image string
 * @param {number} size 0-100 % logo coverage
 */
const addQRLogo = async function(code, logo, size) {
    let codeImg = await Image.load(code);
    let logoImg = await Image.load(logo);

    let targetWith = Math.floor(codeImg.width / 100 * size);
    logoImg = logoImg.resize({ width: targetWith });

    let x = Math.floor((codeImg.width - logoImg.width) / 2);
    let y = Math.floor((codeImg.height - logoImg.height) / 2);

    codeImg.insert(logoImg, { x: x, y: y, inPlace: true });

    return `data:image/png;base64,${codeImg.toBase64('image/png')}`;
}

const readQRCode = async function(code) {
    let codeImg = await Image.load(code);

    let completed = new Promise(function(resolve, reject) {
        let qr = new QrCode();
        qr.callback = function(err, result) {
            if (err) {
                return reject(err + '. If you use a logo, please try to change its size.');
            }
            resolve(result);
        };
        qr.decode(codeImg);
    });

    return await completed;
}

module.exports = { addBreadcrump, base64PNG, addQRLogo, readQRCode };