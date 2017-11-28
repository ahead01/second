const bcrypt = require('bcrypt-nodejs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: [true, 'Username already in use!'] },
    fname: { type: String, required: [true, 'First Name is required!'] },
    lname: { type: String, required: [true, 'Last Name is required!'] },
    email: { type: String, unique: [true, 'Email already in use!'] },
    password: String,
    passwordResetToken: String,
    passwordResetExpires: Date,

    facebook: String,
    twitter: String,
    googleId: String,
    github: String,
    instagram: String,
    linkedin: String,
    steam: String,
    tokens: Array,

    profile: {
        fullName: String,
        gender: String,
        location: String,
        website: String,
        picture: String
    }
}, {strict: true},{ timestamps: true }, { collection: 'auth-users'});

/**
 * Password hash middleware.
 */
UserSchema.pre('save', function save(next) {
    // Dont need this anymore because of passport-local-mongoose !
    var user = this;
    if (!user.isModified('password')) {
        return next();
    }
    bcrypt.genSalt(2, function(err, salt) {
        if (err) { return next(err); }
        bcrypt.hash(user.password, salt, null, function(err, hash) {
        if (err) { return next(err); }
        user.password = hash;
    next();
});
});

});

/**
 * Helper method for validating user's password.
*/
UserSchema.methods.comparePassword = function comparePassword(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch)  {
        cb(err, isMatch);
});
};


/*
Expose the find and modify method

UserSchema.statics.findAndModify2 = function(query){
    return this.collection.findAndModify({query: query, update: true, new: true, upsert: true, setDefaultsOnInsert: true});
};

*/

/**
 * Helper method for getting user's gravatar.

userSchema.methods.gravatar = function gravatar(size) {
    if (!size) {
        size = 200;
    }
    if (!this.email) {
        return `https://gravatar.com/avatar/?s=${size}&d=retro`;
    }
    const md5 = crypto.createHash('md5').update(this.email).digest('hex');
    return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};
 */

//userSchema.plugin(passportLocalMongoose, {usernameField: "userName"});


//UserSchema.plugin(passportLocalMongoose, {usernameField: "userName"});

module.exports = mongoose.model('User', UserSchema);