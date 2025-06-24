const mongoose = require('mongoose');

const SeatSchema = new mongoose.Schema({
    seatID: String,
    scheduleID: String, 
    building: String,
    userID: Number,
    isAvailable: Boolean,
    isAnonymous: Boolean,
    date: String, // Added to facilitate querying
    time: String  // Added to facilitate querying
});

const Seat = mongoose.model('Seat', SeatSchema);

module.exports = Seat;
