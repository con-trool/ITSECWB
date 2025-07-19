const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
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
  securityAnswer: String,

  // 🔐 Add these two fields:
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  }
});

module.exports = mongoose.model('User', userSchema);
