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

    blendInsert(logoImg, codeImg, x, y);

    return `data:image/png;base64,${codeImg.toBase64('image/png')}`;
}

/**
 * Inserts a image into another. Pixels will be blended according to ALPHA channels
 * @param {Image} from Image to intert
 * @param {Image} to Image to insert to
 * @param {number} x X location in target image
 * @param {number} y Z location in target image
 */
function blendInsert(from, to, x, y) {
    let srcPixel = [];
    let targetPixel = [];
    let posX = 0;
    let posY = 0;
    const srcAddAlpha = from.alpha === 0;
    const targetAddAlpha = to.alpha === 0;
    const srcChannelDiff = to.components - from.components;
    const alphaChannel = to.components;
    const divider = 255 * 255;

    // Iterate through all pixels
    for (let iX = 0; iX < from.width; iX++) {
        posX = x + iX;
        if (posX < to.width) {
            for (let iY = 0; iY < from.height; iY++) {
                posY = y + iY;
                if (posY < to.height) {
                    // Get pixel data
                    srcPixel = from.getPixelXY(iX, iY);
                    if (!srcAddAlpha && srcPixel[from.components] === 0) {
                        // src ALPHA = 0
                        continue;
                    }

                    targetPixel = to.getPixelXY(posX, posY);

                    // Adjust to target channel count
                    if (srcChannelDiff < 0) {
                        srcPixel = srcPixel.slice(0, srcPixel.length + srcChannelDiff);
                    } else if (srcChannelDiff > 0) {
                        for (let i = 0; i < srcChannelDiff; i++) {
                            srcPixel.push(srcPixel[0]);
                        }
                    }

                    // Add ALPHA channels
                    if (srcAddAlpha) {
                        srcPixel.push(255);
                    }
                    if (targetAddAlpha) {
                        targetPixel.push(255);
                    }

                    // Blend pixels
                    for (let i = 0; i < targetPixel.length; i++) {
                        if (i === alphaChannel) {
                            targetPixel[alphaChannel] = srcPixel[alphaChannel] + (targetPixel[alphaChannel] * (255 - srcPixel[alphaChannel]) / 255)
                        } else {
                            targetPixel[i] = (srcPixel[i] * srcPixel[alphaChannel] / 255) + (targetPixel[i] * targetPixel[alphaChannel] * (255 - srcPixel[alphaChannel]) / divider);
                        }
                    }

                    // Remove ALPHA channel, if added for calculation
                    if (targetAddAlpha) {
                        targetPixel = targetPixel.slice(0, targetPixel.length - 1);
                    }

                    // Set target pixel
                    to.setPixelXY(posX, posY, targetPixel);
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
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