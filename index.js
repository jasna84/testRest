var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var routes = require('./routes');
var config = require('./config');
//var jwt = require('jsonwebtoken');
//var bcrypt = require('bcryptjs');
//var User = require('./user');


//configuration

const url = 'mongodb://localhost/testPassport';
var port = process.env.PORT || 3000;
app.set('superSecret', config.secret);

//connection with the database

mongoose.connect(url, { useMongoClient: true });
var db = mongoose.connection;

db.on('error', function(err) {
    if (err) throw err;
});

db.once('open', function callback() {
    console.info('Mongo db connected successfully on ', url);
});

// // use body parser so we can get info from POST and/or URL parameters

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// // use morgan to log requests to the console

app.use(morgan('dev'));

app.use('/', routes);

//start the server

app.listen(port);
console.log('Server is running on http://localhost:' + port);