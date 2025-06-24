const mongoose = require('mongoose');
const Building = require('./database/models/Building');
const Schedule = require('./database/models/Schedule');
const Seat = require('./database/models/Seat');

const uri = "mongodb://localhost:27017/labSpotDB";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
mongoose.connect(uri, {
  serverSelectionTimeoutMS: 50000, // Increase timeout to 50 seconds
  connectTimeoutMS: 50000 // Increase connection timeout to 50 seconds
}).then(() => {
  console.log('MongoDB connected...');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

const buildings = [
  { name: 'Velasco', seatCount: 15 },
  { name: 'Br. Andrew Gonzales', seatCount: 40 },
  { name: 'Gokongwei', seatCount: 20 }
];

const times = [
  '7:30-8:00', '8:15-8:45', '9:00-9:30', '9:45-10:15',
  '10:30-11:00', '11:15-11:45', '12:00-12:30', '12:45-13:15',
  '13:30-14:00', '14:15-14:45', '15:00-15:30', '15:45-16:15',
  '16:30-17:00'
];

const today = new Date();

const createSchedulesAndSeats = async () => {
  const schedules = [];
  const seats = [];

  for (let i = 0; i < 8; i++) {
    const date = new Date(today);
    date.setDate(today.getDate() + i);
    const dateString = date.toISOString().split('T')[0];

    for (let index = 0; index < times.length; index++) {
      const time = times[index];
      const scheduleID = `${dateString}-${index}`;

      schedules.push({ scheduleID, date: dateString, time });

      buildings.forEach(building => {
        for (let seatIndex = 0; seatIndex < building.seatCount; seatIndex++) {
          seats.push({
            seatID: `${building.name}-${dateString}-${time}-${seatIndex + 1}`,
            scheduleID,
            building: building.name,
            userID: null,
            isAvailable: true,
            isAnonymous: true,
            date: dateString,
            time
          });
        }
      });
    }
  }

  try {
    await Building.deleteMany({});
    await Schedule.deleteMany({});
    await Seat.deleteMany({});

    for (const building of buildings) {
      await Building.updateOne({ name: building.name }, building, { upsert: true });
    }
    console.log('Buildings upserted');

    for (const schedule of schedules) {
      await Schedule.updateOne({ scheduleID: schedule.scheduleID }, schedule, { upsert: true });
    }
    console.log('Schedules upserted');

    for (const seat of seats) {
      await Seat.updateOne({ seatID: seat.seatID }, seat, { upsert: true });
    }
    console.log('Seats upserted');
  } catch (error) {
    console.error('Error inserting data:', error);
  } finally {
    mongoose.connection.close();
  }
};

createSchedulesAndSeats();