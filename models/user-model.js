const bcrypt = require('bcrypt-nodejs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');
const beautifyUnique = require('mongoose-beautiful-unique-validation');


//var custom = [validator, 'Email already in use, please log in with that account'];

const UserSchema = new mongoose.Schema({
    username: { type: String,  unique: 'Username {VALUE} already in use, please try another Username.' },
    fname: { type: String, required: [true, 'First Name is required!'] },
    lname: { type: String, required: [true, 'Last Name is required!'] },
    email: { type: String, unique: 'Email already in use, please log in with that account: {VALUE}' },
    password: String,
    passwordResetToken: String,
    passwordResetExpires: Date,

    facebook: String,
    twitter: String,
    twitterHandle: String,
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
        picture: {type:String, default:'/images/user-default.png'},
        aboutMe: {type:String, default:'This is some sample text for the user\'s about me section. It is defaulted' +
        ' in the mongoose schema and is stored in the mongo database!' },
    }
},{strict: true, timestamps: true , collection: 'AuthUsers',autoIndex: true });

/*
function validator (val) {
    UserSchema.findOne({ email: val }, function(err, existingEmailUser) {
        if (err) { return err; }
        if (existingEmailUser) {
            return false;
        }else{
            return true;
        }
    });
}
*/

// Enable beautifying on this schema
UserSchema.plugin(beautifyUnique);
// otherwise unique constraints may be violated.
/*
UserSchema.on('index', function(error) {
    assert.ifError(error);
    U2.create(dup, function(error) {
        // Will error, but will *not* be a mongoose validation error, it will be
        // a duplicate key error.
        assert.ok(error);
        assert.ok(!error.errors);
        assert.ok(error.message.indexOf('duplicate key error') !== -1);
    });
});

UserSchema.set(strict, true);
UserSchema.set(timestamps, true);
UserSchema.set(collection, 'AuthUsers');
UserSchema.set(autoIndex, false);
*/



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

UserSchema.methods.isPasswordValid = function(rawPassword, callback) {
    bcrypt.compare(rawPassword, this.password, function(err, same) {
        if (err) {
            callback(err);
        }
        callback(null, same);
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