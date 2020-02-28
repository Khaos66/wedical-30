const debug = require('debug')('wedical:mailer');
const nodemailer = require('nodemailer');
const pug = require('pug');
const fs = require('fs');
const path = require('path');
const i18n = require('i18n');
const i18nExt = require('./extension/i18n-ext');
const config = require('./config');

const sendmail = function(req, to, template, data) {
    // setup SMTP transport
    let transporter = nodemailer.createTransport(config.smtp);

    // load tempalted mail
    let pugFn = pug.compileFile(`./mails/${template}/template.pug`, {
        cache: false
    });

    // enable locales
    let catalog = i18n.getCatalog();
    if (catalog) {
        for(var locale in catalog) {
            let file = `./mails/${template}/${locale}.json`;
            if (fs.existsSync(file)) {
                i18nExt.addLocaleFile(locale, file);
            }
        }
    }
    //i18nExt.addLocaleFile()
    data.__ = function() {
        return i18n.__.apply(req, arguments);
    };

    // generate HTML message
    let htmlMessage = pugFn(data);

    // extract title
    let titlePattern = /<title>([\W\w]*)<\/title>/gi;
    let title = titlePattern.exec(htmlMessage);
    if (!title) {
        title = 'Party-Mail';
    } else {
        title = title[1];
    }

    // Send message
    let message = {
        from: config.mailFrom,
        to: to,
        subject: title,
        html: htmlMessage,
    };

    // add attachements
    let attachDir = `./mails/${template}/attach`;
    if (fs.existsSync(attachDir)) {
        let files = fs.readdirSync(attachDir);
        message.attachments = files.map(x => { return { 
            filename: x, 
            cid: x,
            path: path.join(attachDir, x)}; });
    }

    transporter.sendMail(message, function(err, info, response) {
        if (err) {
            debug.log(`Error while sending email: ${err}`);
        }else if (info) {
            debug.log(`Successfully sended email`);
        }
    });
}

module.exports = sendmail;