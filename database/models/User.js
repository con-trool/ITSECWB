const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    userID: Number,
    username: String,
    password: String,
    name: String,
    college: String,
    program: String,
    description: String,
    image: String,
    isTechnician: Boolean,
    securityQuestion: String,
    securityAnswer: String
});

const User = mongoose.model('User', UserSchema);

module.exports = User;
