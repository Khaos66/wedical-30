var express = require('express');
var router = express.Router();

// Define the invite page route.
router.get('/', function(req, res) {
  res.render('invite', null);
});

module.exports = router;
