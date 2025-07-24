const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userID: Number,
  username: {
    type: String,
    required: true,
    maxlength: 100 // Enforce email max length
  },
  password: {
    type: String,
    required: true,
    maxlength: 64, // Enforce hashed password length (safe margin)
  },
  name: String,
  college: String,
  program: String,
  description: String,
  image: String,
  isTechnician: Boolean,
  securityQuestion: String,
  securityAnswer: {
    type: String,
    required: true,
    maxlength: 100 // Enforce max answer length
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  passwordHistory: {
    type: [String],  // Array of hashed passwords
    default: []
  },
});



module.exports = mongoose.model('User', userSchema);
