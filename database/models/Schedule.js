const mongoose = require('mongoose');

const ScheduleSchema = new mongoose.Schema({
    scheduleID: String,
    date: String,
    time: String
});

const Schedule = mongoose.model('Schedule', ScheduleSchema);

module.exports = Schedule;
