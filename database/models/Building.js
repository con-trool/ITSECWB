const mongoose = require('mongoose');

const BuildingSchema = new mongoose.Schema({
    name: String
});

const Building = mongoose.model('Building', BuildingSchema);

module.exports = Building;
