const app = require('./app');
const http = require('http');

// host app in Phusion Passenger
http.createServer(app).listen(process.env.PORT);