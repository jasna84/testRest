var express = require('express');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var User = require('./user');
var config = require('./config/config');
var passport = require('./config/passport');
var async = require('async');
var crypto = require('crypto');

var app = express();
var routes = express.Router();
var port = process.env.PORT || 3000;

// unprotected routes

routes.get('/', function(req, res) {
    res.send('Hello! Please proceed to http://localhost:' + port + '/home');
});

routes.get('/home', function(req, res) {
    res.send('Please register at http://localhost:' + port + '/home/register' + ' or login at http://localhost:' + port + '/home/login');
});

// //create a new user, unprotected route 

routes.post('/home/register', function(req, res) {

    console.log(req.body);
    if (!req.body.username || !req.body.password) {
        res.json({ success: false, msg: 'Please pass username and password.' });
    } else {
        var newUser = new User({
            username: req.body.username,
            password: req.body.password,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email_address: req.body.email_address
        });

        // save the new user

        User.createUser(newUser, function(err, user) {
            if (err) {
                res.json({ success: false, msg: 'Username already exists.' });
            } else {

                const payload = {
                    admin: newUser.admin,
                    userID: newUser._id
                };

                var token = jwt.sign(payload, config.secret, {
                    expiresIn: 60 * 60 * 24

                });

                res.json({
                    success: true,
                    message: 'Successfully created new user',
                    token: token
                });
            }
        });
    }
});

/*routes.post('/home/forgot', function(req, res, next) {
    async.waterfall([
        function(done) {
            crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },
        function(token, done) {
            console.log(req.body);
            User.findOne({ email: req.body.email_address }, function(err, user) {
                if (!user) {
                    res.json({ success: false, msg: 'No account with that email address exists.' });
                } else {

                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
                    user.save(function(err) {
                        done(err, token, user);
                    });
                }
            });
        },
        function(token, user, done) {
            var smtpTransport = nodemailer.createTransport('SMTP', {
                service: 'SendGrid',
                auth: {
                    user: '!!! YOUR SENDGRID USERNAME !!!',
                    pass: '!!! YOUR SENDGRID PASSWORD !!!'
                }
            });
            var mailOptions = {
                to: user.email,
                from: 'passwordreset@demo.com',
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err) {
                req.json({ msg: 'An e-mail has been sent to ' + user.email + ' with further instructions.' });
                done(err, 'done');
            });
        }
    ], function(err) {
        if (err) return next(err);
        res.redirect('/forgot');
    });
});*/

routes.post('/home/login', function(req, res) {

    // find the user, if they exist issue a token

    User.findOne({
        username: req.body.username
    }, function(err, user) {

        if (err) throw err;
        console.log(user);
        if (!user) {
            console.log(user)
            res.json({ success: false, message: 'Authentication failed. User not found.' });
        } else {
            console.log(user);
            User.comparePasswords(req.body.password, user.password, function(err, isMatch) {
                if (isMatch && !err) {
                    const payload = {
                        admin: user.admin,
                        userId: user._id
                    };

                    var token = jwt.sign(payload, config.secret, {
                        expiresIn: 60 * 60 * 24

                    });

                    res.json({
                        success: true,
                        token: token
                    });
                    //return res.redirect('/home/profile');

                } else {
                    res.json({ success: false, message: 'Authentication failed. Wrong password.' });
                }
            });
        }
    });
});

routes.get('/home/login/facebook', passport.authenticate('facebook', { scope: ['email'] }));

routes.get('/home/login/facebook/callback',
    passport.authenticate('facebook', {
        successRedirect: '/home/login/profile',
        failureRedirect: '/home/login'
    }));

// // route middleware to verify a token

routes.use(function(req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, config.secret, function(err, decoded) {
            if (err) {
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded;
                next();
            }
        });
    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
    }
});

// //protected route, access with token only

routes.get('/home/login/logout', function(req, res) {
    res.json({ success: true, message: 'You logged out successfully', token: null });
});

routes.get('/home/login/profile', function(req, res) {

    //res.json({ message: 'Congrats, you sucesfully used your token' });
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    var decoded = jwt.decode(token, { complete: true });

    console.log(decoded.payload);

    User.findById(decoded.payload.userId, function(err, user) {
        console.log(decoded.payload.userId);
        if (err) return res.status(500).send("There was a problem finding the user.");
        if (!user) return res.status(404).send("No user found.");
        res.status(200).send(user);
    });
});

/*routes.post('/home/login/profile/reset', function(req, res) {
    console.log(req.body);
    
}*/

module.exports = routes;