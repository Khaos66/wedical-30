const debug = require('debug')('wedical:qrprint');
const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const { Auth } = require('../../../auth');
const { addBreadcrump } = require('../../../utils');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const Invite = require('../../../models/invite');

// CSRF
var csrfProtection = csrf();

// Define the invites page route.
router.get('/',
    csrfProtection,
    Auth.authenticate('/manage/invites/qrprint'),
    Auth.authorize('manage', { 'Segment': 'invites' }),
    addBreadcrump('Print QR Codes', '/manage/invites/qrprint'),
    async function(req, res) {
        res.render('manage/invites/qrprint', {
            csrfToken: req.csrfToken(),
        });
    });

// Download QR Codes as PDF route
router.post('/',
    csrfProtection,
    Auth.authenticate(false),
    Auth.authorize('manage', { 'Segment': 'invites' }),
    downloadPDF
);

async function downloadPDF(req, res) {
    // Create new document
    const pdfDoc = await PDFDocument.create();

    // Embed the Times Roman font
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const black = rgb(0, 0, 0);

    // select invites
    let invites = await Invite.find();

    let padding = 20;
    let qrScale = 0.5;
    let titleFontSize = 10;
    let urlFontSize = 8;
    let urlPadding = 4;

    let posX = 0;
    let posY = 0;
    let page = null;
    let pageWidth = 0;
    let pageHeight = 0;
    let url = '';
    let qrcode = null;
    let cardWidth = 0;
    let cardHeight = 0;
    let pngImage = null;
    let pngDims = null;
    let titleWidth = 0;
    let titleXOffset = 0;
    let imagePosX = 0;
    let urlWidth = 0;
    let urlXOffset = 0;
    let urlYOffset = 0;

    let urlHeight = font.heightAtSize(urlFontSize);
    let titleHeight = font.heightAtSize(titleFontSize);
    let imageYOffset = titleHeight + 2;

    // iterate through all invites
    for (var invite of invites) {
        pngImage = null;

        // things to print
        url = invite.getInviteUrl();
        qrcode = await invite.getQRCode();

        // Embed and scale image
        if (qrcode.img) {
            pngImage = await pdfDoc.embedPng(qrcode.img);
            pngDims = pngImage.scale(qrScale);
            if (cardWidth === 0) {
                cardWidth = pngDims.width + padding;
                cardHeight = cardWidth + titleHeight + padding;
            }
        }

        // Calc width of URL
        urlWidth = font.widthOfTextAtSize(url, urlFontSize);
        if (urlWidth + padding > cardWidth) {
            cardWidth = urlWidth + padding;
        }

        // Add a new page if nessecary
        if (!page || (posX + cardWidth > pageWidth && posY - cardHeight < padding)) {
            // Add a blank page to the document
            page = pdfDoc.addPage();

            // Get the width and height of the page
            var { width, height } = page.getSize();
            pageWidth = width;
            pageHeight = height;

            posX = padding;
            posY = pageHeight - padding - titleHeight;
            page.moveTo(posX, posY);
        }

        // Draw: Title
        titleWidth = font.widthOfTextAtSize(invite.title, titleFontSize);
        titleXOffset = Math.floor((cardWidth - titleWidth) / 2);
        page.drawText(invite.title, {
            x: posX + titleXOffset,
            size: titleFontSize,
            font: font,
            color: black
        });
        // Draw: URL
        urlXOffset = Math.floor((cardWidth - urlWidth) / 2);
        urlYOffset = pngDims.height + imageYOffset + urlHeight + urlPadding;
        page.drawText(url, {
            x: posX + urlXOffset,
            y: posY - urlYOffset,
            size: urlFontSize,
            font: font,
            color: black
        });

        // Draw: QR Code
        if (pngImage) {
            imagePosX = posX + Math.floor((cardWidth - pngDims.width) / 2);
            page.drawImage(pngImage, {
                x: imagePosX,
                y: posY - pngDims.height - imageYOffset,
                width: pngDims.width,
                height: pngDims.height
            });
            // Draw broder
            // left
            page.drawLine({
                start: { x: imagePosX, y: posY - pngDims.height - imageYOffset },
                end: { x: imagePosX, y: posY - imageYOffset },
                thickness: 1,
                color: black
            });
            // right
            page.drawLine({
                start: { x: imagePosX + pngDims.width, y: posY - pngDims.height - imageYOffset },
                end: { x: imagePosX + pngDims.width, y: posY - imageYOffset },
                thickness: 1,
                color: black
            });
            // top
            page.drawLine({
                start: { x: imagePosX, y: posY - imageYOffset },
                end: { x: imagePosX + pngDims.width, y: posY - imageYOffset },
                thickness: 1,
                color: black
            });
            // bottom
            page.drawLine({
                start: { x: imagePosX, y: posY - pngDims.height - imageYOffset },
                end: { x: imagePosX + pngDims.width, y: posY - pngDims.height - imageYOffset },
                thickness: 1,
                color: black
            });
        }

        // move to next card
        posX += cardWidth;
        if (posX + cardWidth > pageWidth) {
            posY -= cardHeight;
            posX = padding;
        }
        page.moveTo(posX, posY);
    }

    // Serialize the PDFDocument to bytes (a Uint8Array)
    const pdfBytes = await pdfDoc.save();

    // Send PDF
    res.setHeader('Content-disposition', 'attachment; filename=QRCodes.pdf');
    res.setHeader('Content-Transfer-Encoding', 'binary');
    res.setHeader('Content-Type', 'application/pdf');
    res.send(new Buffer(pdfBytes, 'binary'));
}

module.exports = router;