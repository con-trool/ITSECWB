const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userID: Number,
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 254,                // ⬅️ was 100
    validate: [
      {
        validator: v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
        message: 'Invalid email format.'
      },
      {
        validator: v => v.endsWith('@dlsu.edu.ph'),
        message: 'Must use a DLSU email.'
      }
    ]
  },
  password: {
    type: String,
    required: true,
    maxlength: 64
  },
  name: String,
  college: String,
  program: String,
  description: String,
  image: String,
  isTechnician: Boolean,
  isAdmin: Boolean,
  securityQuestion: String,
  securityAnswer: {
    type: String,
    required: true,
    maxlength: 100
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
    type: [String],
    default: []
  },
  lastPasswordChange: {
    type: Date,
    default: Date.now
  },
  lastLoginAttempt: {
  type: Date,
  default: null
  },
  lastLoginSuccess: {
    type: Boolean,
    default: null
  }

});




module.exports = mongoose.model('User', userSchema);
