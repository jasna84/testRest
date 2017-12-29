// get an instance of mongoose and mongoose.Schema
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcryptjs');
var async = require('async');
var crypto = require('crypto');

// set up a mongoose model and pass it using module.exports
module.exports = mongoose.model('User', new Schema({
    local: {
        username: { type: String, unique: true, required: true },
        password: { type: String, required: true },
        firstName: String,
        lastName: String,
        email_address: String,
        admin: Boolean,
        resetPasswordToken: String,
        resetPasswordExpires: Date
    },
    facebook: {
        id: String,
        token: String,
        email: String,
        name: String
    }
}));

module.exports.createUser = function(newUser, callback) {
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(newUser.password, salt, function(err, hash) {
            // Store hash in your password DB
            newUser.password = hash;
            newUser.save(callback);
        });
    });
};

module.exports.comparePasswords = function(password, hash, callback) {
    bcrypt.compare(password, hash, function(err, isMatch) {
        if (err) throw err;
        callback(null, isMatch);
    });
};

/*module.exports.forgotPassword = function(req, res) {
    async.waterfall([
        function(done) {
            User.findOne({
                email: req.body.email_address
            }).exec(function(err, user) {
                if (user) {
                    done(err, user);
                } else {
                    done('User not found.');
                }
            });
        },
        function(user, done) {
            // create the random token
            crypto.randomBytes(20, function(err, buffer) {
                var token = buffer.toString('hex');
                done(err, user, token);
            });
        },
        function(user, token, done) {
            User.findByIdAndUpdate({ _id: user._id }, { reset_password_token: token, reset_password_expires: Date.now() + 86400000 }, { upsert: true, new: true }).exec(function(err, new_user) {
                done(err, token, new_user);
            });
        },
        function(token, user, done) {
            var data = {
                to: user.email,
                from: email,
                template: 'forgot-password-email',
                subject: 'Password help has arrived!',
                context: {
                    url: 'http://localhost:3000/auth/reset_password?token=' + token,
                    name: user.fullName.split(' ')[0]
                }
            };
            smtpTransport.sendMail(data, function(err) {
                if (!err) {
                    return res.json({ message: 'Please check your email for further instructions' });
                } else {
                    return done(err);
                }
            });
        }
    ], function(err) {
        return res.status(422).json({ message: err });
    });
};*/