const nodemailer = require('nodemailer');
const config = require('./config');

const sendmail = function(to, template, data) {
    // setup SMTP transport
    let transport = nodemailer.createTransport(config.smtp);

    // load tempalted mail

    // Send message
    let message = {
        from: config.mailFrom,
        to: to,
        subject: 'testmail',
        html: '<p>Test</p>',
    };
    transporter.sendMail(message);
}

module.exports = sendmail;