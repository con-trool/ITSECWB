const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  userID: { type: Number, required: true },
  role: { type: String, enum: ['student', 'technician', 'admin'], required: true },
  action: { type: String, required: true },
  details: { type: mongoose.Schema.Types.Mixed }, // string or object
  status: { type: String, enum: ['success', 'failure'], required: true }
});

const Log = mongoose.model('Log', LogSchema);

module.exports = Log;
