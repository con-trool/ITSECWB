const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const fileUpload = require('express-fileupload');
const User = require('./database/models/User');
const schedule = require('node-schedule');
const Seat = require('./database/models/Seat');
const path = require('path');
const bodyParser = require('body-parser');
const hbs = require('hbs');

hbs.registerHelper('lookup', function (obj, field, attr) {
  return (obj && obj[field]) ? obj[field][attr] : '';
});
hbs.registerHelper('substring', function (seatID) {
  return seatID.split('-').pop(); // Adjust this logic according to the seatID format
});
hbs.registerHelper('increment', function (index) {
  return index + 1;
});
hbs.registerHelper('isGuestUser', function(userId, options) {
  return userId === 1 ? options.fn(this) : options.inverse(this);
});
hbs.registerHelper('eq', function (a, b) {
  return a == b;
});
const app = express();
app.set('view engine', 'hbs');

// MongoDB Atlas connection URI
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(fileUpload());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(__dirname));
app.use(express.static('css'));
app.use(express.static('img'));
app.use(express.static('font-awesome-4.7.0'));
app.use(express.static('html'));
app.use(cookieParser());

// Session management
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: uri }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Middleware to check if the user is authenticated
async function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next(); // User is authenticated, proceed to the next middleware or route handler
  } else if (req.cookies.rememberMe) {
    const { email, password } = req.cookies.rememberMe;
    const user = await User.findOne({ username: email });

    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        req.session.userId = user._id.toString();
        req.session.isTechnician = user.isTechnician;
        return next();
      }
    }
    res.redirect('/login'); // Invalid cookie credentials, redirect to login
  } else {
    res.redirect('/login'); // User is not authenticated, redirect to login
  }
}

// Middleware to allow guest users
const allowGuest = (req, res, next) => {
  if (req.query.guest === 'true') {
    req.isGuest = true;
  } else {
    req.isGuest = false;
  }
  next();
};
app.get('/menu', allowGuest, async (req, res) => {
  try {
    let user;
    if (req.isGuest) {
      user = { userID: 1, isTechnician: false, name: 'Guest' }; // Guest user details
      console.log('Accessing menu as guest');
    } else {
      user = await User.findById(req.session.userId);
      if (!user) {
        return res.redirect('/login');
      }
    }
    const userId = user.userID;
    const isTechnician = user.isTechnician;
    console.log('User ID:', userId);
    console.log('Is Technician:', isTechnician);
    res.render('menu', { userId, isTechnician, isGuest: req.isGuest });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/GOKSreserve', allowGuest, async (req, res) => {
  try {
    let user;
    if (req.isGuest) {
      user = { userID: 1, isTechnician: false, name: 'Guest' }; // Guest user details
      console.log('Accessing GOKSreserve as guest');
    } else {
      console.log('Accessing GOKSreserve as logged-in user');
      user = await User.findById(req.session.userId);
      if (!user) {
        console.log('User not found, redirecting to login');
        return res.redirect('/login');
      }
    }
    console.log('User ID:', user.userID);
    res.render('GOKSreserve', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/reservation', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const userId = user.userID;
    console.log('User ID from session:', userId);

    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const skip = (page - 1) * limit;

    console.log('Parsed User ID:', userId);

    const seats = await Seat.find({ userID: userId })
      .skip(skip)
      .limit(limit)
      .exec();

    console.log('Fetched seats:', seats);

    const count = await Seat.countDocuments({ userID: userId });
    console.log('Total count of seats:', count);

    const totalPages = Math.ceil(count / limit);
    console.log('Total pages:', totalPages);

    res.render('reservation', {
      user,
      seats,
      currentPage: page,
      totalPages,
      prevPage: page > 1 ? page - 1 : null,
      nextPage: page < totalPages ? page + 1 : null
    });
  } catch (error) {
    console.error('Error fetching reservations:', error);
    res.status(500).send('Server error');
  }
});

app.get('/profile/:id', isAuthenticated, async (req, res) => {
  try {
    const userID = parseInt(req.params.id, 10); // Ensure userID is an integer
    if (isNaN(userID)) {
      return res.status(400).send('Invalid userID');
    }

    const user = await User.findOne({ userID });
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.render('otherprofile', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/forgotpassword', function (req, res) {
  res.render('forgotpassword'); // No data needed initially
});

// Routes that don't require authentication
app.get('/login', function (req, res) {
  let credentials = { email: '', password: '' };
  
  if (req.cookies.rememberMe) {
    const { email, password } = req.cookies.rememberMe;
    credentials.email = email;
    credentials.password = password;
  }

  res.render('login', { credentials });
});

app.post('/login', async (req, res) => {
  const { email, password, rememberMe, name } = req.body;
  try {
    const user = await User.findOne({ username: email });

    // Check if user exists
    if (!user) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    // User exists, now compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    // Set session variables upon successful login
    req.session.userId = user._id.toString();
    req.session.isTechnician = user.isTechnician;

    // Set cookie if "Remember Me" is checked
    if (rememberMe) {
      res.cookie('rememberMe', { email, password }, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true }); // 30 days
    } else {
      res.clearCookie('rememberMe');
    }

    // Render different pages based on user type
    if (user.isTechnician) {
      res.redirect('/technicianpage');
    } else {
      res.redirect('/menu');
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error');
  }
});

app.get('/technicianpage', isAuthenticated, async (req, res) => {
  try {
    const seats = await Seat.find({ isAvailable: false }).exec();
    const users = await User.find({}).exec(); // Fetch all users

    // Create a map of users for easy lookup
    const usersMap = users.reduce((map, user) => {
      if (user.userID) {
        map[user.userID.toString()] = user;
      }
      return map;
    }, {});

    console.log('Seats:', seats);
    console.log('Users:', usersMap);

    res.render('technicianpage', {
      user: req.session.user,
      seats: seats,
      users: usersMap // Pass usersMap to the template
    });
  } catch (error) {
    console.error('Error fetching reservations:', error);
    res.status(500).send('Server error');
  }
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const {
      email,
      password,
      confirmPassword,
      securityQuestion,
      securityAnswer,
      isTechnician
    } = req.body;

    if (!email || !password || !confirmPassword || !securityQuestion || !securityAnswer) {
      return res.send(`<script>alert('All fields are required.'); window.history.back();</script>`);
    }

    if (!email.endsWith('@dlsu.edu.ph')) {
      return res.send(`<script>alert('Email must end with @dlsu.edu.ph'); window.history.back();</script>`);
    }

    if (password !== confirmPassword) {
      return res.send(`<script>alert('Passwords do not match.'); window.history.back();</script>`);
    }

    const existingUser = await User.findOne({ username: email });
    if (existingUser) {
      return res.send(`<script>alert('Unable to register with provided information.'); window.history.back();</script>`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Extract name from email
    const localPart = email.split('@')[0]; 
    const name = localPart
      .split('_')
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' '); 

    const newUser = new User({
      username: email,
      password: hashedPassword,
      name: name,
      securityQuestion,
      securityAnswer,
      isTechnician: isTechnician === 'true',
      userID: Date.now()
    });

    await newUser.save();
    console.log("New user saved:", newUser);

    res.json({ success: true });
  } catch (error) {
    console.error("Error registering new user:", error);
    res.json({ success: false, message: 'Error registering new user.' });
  }
});


  app.post('/check-email', async function (req, res) {
    const { email } = req.body;

    try {
      // Check if the email is already registered
      const existingUser = await User.findOne({ username: email });
      if (existingUser) {
        return res.json({ exists: true });
      } else {
        return res.json({ exists: false });
      }
    } catch (error) {
      console.error("Error checking email:", error);
      res.status(500).send("Error checking email.");
    }
  });


app.post('/forgot/check-email', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ username: email });
    if (!user) {
      return res.json({ exists: false });
    }

    // Return question (e.g., convert ID to readable form if needed)
    const questions = {
      pet: "What is the name of your first pet?",
      school: "What was the name of your elementary school?",
      city: "In what city were you born?",
      nickname: "What is your childhood nickname?",
      food: "What is your favorite food?"
    };

    res.json({
      exists: true,
      question: questions[user.securityQuestion] || "Security Question"
    });
  } catch (error) {
    console.error("Error checking email:", error);
    res.status(500).send("Internal server error");
  }
});

// 2. Check if security answer is correct
app.post('/forgot/check-answer', async (req, res) => {
  const { email, answer } = req.body;

  try {
    const user = await User.findOne({ username: email });
    if (!user) return res.json({ valid: false });

    const isValid = user.securityAnswer.trim().toLowerCase() === answer.trim().toLowerCase();
    res.json({ valid: isValid });
  } catch (error) {
    console.error("Error checking answer:", error);
    res.status(500).send("Internal server error");
  }
});

// 3. Reset the password
app.post('/forgot/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ username: email });
    if (!user) return res.json({ success: false });

    const hashed = await bcrypt.hash(newPassword, 10); // Optional but recommended
    user.password = hashed;
    await user.save();

    res.json({ success: true });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).send("Internal server error");
  }
});   
// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.redirect('/login');
  });
});

app.get('/userprofile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('userprofile', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/edituserpage', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('edituserpage', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.post('/update-user', isAuthenticated, async (req, res) => {
  const { name, college, program, description } = req.body;

  try {
    const user = await User.findById(req.session.userId);
    user.name = name;
    user.college = college;
    user.program = program;
    user.description = description;

    if (req.files && req.files.picture) {
      const picture = req.files.picture;
      const picturePath = path.join(__dirname, 'public', 'uploads', picture.name);
      await picture.mv(picturePath);
      user.image = `/uploads/${picture.name}`;
    }

    await user.save();
    res.redirect('/userprofile');
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/deleteprofile', isAuthenticated, function (req, res) {
  res.sendFile(__dirname + "/deleteprofile.html");
});

app.get('/AGreserve', allowGuest, async (req, res) => {
  try {
    let user;
    if (req.isGuest) {
      user = { userID: 1, isTechnician: false, name: 'Guest' }; // Guest user details
    } else {
      user = await User.findById(req.session.userId);
      if (!user) {
        return res.redirect('/login');
      }
    }
    res.render('AGreserve', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/api/seats', async (req, res) => {
  try {
    const { date, timeslot, building } = req.query;
    const seats = await Seat.find({ date, time: timeslot, building });
    res.json(seats);
  } catch (error) {
    console.error('Error fetching seats:', error);
    res.status(500).send('Server error');
  }
});

app.get('/api/user/:id', async (req, res) => {
  try {
    const userID = parseInt(req.params.id, 10);
    if (isNaN(userID)) {
      return res.status(400).json({ message: 'Invalid userID' });
    }
    const user = await User.findOne({ userID });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.post('/api/reserve', isAuthenticated, async (req, res) => {
  const { date, timeslot, seatID, isAnonymous, userID } = req.body;
  console.log('Reservation request received with the following details:');
  console.log('Date:', date);
  console.log('Time:', timeslot);
  console.log('SeatID:', seatID);
  console.log('IsAnonymous:', isAnonymous);
  console.log('UserID:', userID);

  try {
    const seat = await Seat.findOne({ seatID, date, time: timeslot });
    console.log('Fetched seat from database:', seat);
    if (!seat) {
      return res.status(404).json({ success: false, message: 'Seat not found' });
    }

    if (!seat.isAvailable) {
      return res.status(400).json({ success: false, message: 'Seat is already reserved' });
    }

    seat.isAvailable = false;
    seat.userID = userID;
    seat.isAnonymous = isAnonymous;

    await seat.save();
    console.log('Seat reserved successfully:', seat);
    res.json({ success: true });
  } catch (error) {
    console.error('Error reserving seat:', error);
    res.status(500).send('Error reserving seat.');
  }
});

// Other public routes
app.get('/index', function (req, res) {
  res.sendFile(__dirname + "/index.html");
});

app.get('/forgot_password', function (req, res) {
  res.sendFile(__dirname + "/forgotpassword.html");
});

app.get('/freeslotsearch', function (req, res) {
  res.sendFile(__dirname + "/freeslotsearch.html");
});


app.get('/VELreserve', allowGuest, async (req, res) => {
  try {
    let user;
    if (req.isGuest) {
      user = { userID: 1, isTechnician: false, name: 'Guest' }; // Guest user details
    } else {
      user = await User.findById(req.session.userId);
      if (!user) {
        return res.redirect('/login');
      }
    }
    res.render('VELreserve', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Server error');
  }
});

app.get('/api/users', async (req, res) => {
  const { query, college, degree } = req.query;

  try {
    const filter = { isTechnician: false ,  userID: { $ne: 1 }   };

    if (query) {
      filter.name = { $regex: query, $options: 'i' }; // Case-insensitive search
    }

    if (college) {
      filter.college = college;
    }

    if (degree) {
      filter.program = degree;
    }

    const users = await User.find(filter);
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).send('Server error');
  }
});

app.get('/api/slots', async (req, res) => {
  const { date, time, building } = req.query;

  try {
    const filter = {};

    if (date) {
      filter.date = date;
    }

    if (time) {
      filter.time = time;
    }

    if (building) {
      filter.building = building;
    }

    // Find all slots that match the criteria and are available
    const slots = await Seat.find({ ...filter, isAvailable: true });

    // Aggregate by counting the available slots per date, time, and building
    const aggregatedSlots = slots.reduce((acc, slot) => {
      const key = `${slot.date}-${slot.time}-${slot.building}`;
      if (!acc[key]) {
        acc[key] = { date: slot.date, time: slot.time, building: slot.building, availableSlots: 0 };
      }
      acc[key].availableSlots += 1;
      return acc;
    }, {});

    // Convert the object to an array for easier handling on the client side
    const result = Object.values(aggregatedSlots);

    res.json(result);
  } catch (error) {
    console.error('Error fetching slots:', error);
    res.status(500).send('Server error');
  }
});

app.post('/submit-form', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ username: email });

    if (!user) {
      // User not found
      return res.json({ success: false, message: 'Invalid email or password' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      // Passwords do not match
      return res.json({ success: false, message: 'Invalid email or password' });
    }

    // Delete the user's reservations
    await Seat.deleteMany({ userID: user.userID });
    console.log('User reservations deleted for userID:', user.userID);

    // Delete the user account
    await User.deleteOne({ _id: user._id });
    console.log('User deleted:', user);

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/cancel', isAuthenticated, async (req, res) => {
  const { date, timeslot, seatID, userID } = req.body;

  try {
      const query = { seatID, date, time: timeslot, userID: userID || null };
      const seat = await Seat.findOne(query);
      if (seat) {
          seat.isAvailable = true;
          seat.userID = null;
          seat.isAnonymous = false;
          await seat.save();
          res.json({ success: true });
      } else {
          res.json({ success: false, message: 'Seat not found or user not authorized to cancel this reservation' });
      }
  } catch (error) {
      res.status(500).send('Server error');
  }
});

app.post('/api/editReservation', isAuthenticated, async (req, res) => {
  const { oldDate, oldTimeslot, oldSeatID, newDate, newTimeslot, newSeatID, userID, isAnonymous } = req.body;
  console.log('Edit reservation request received with:', { oldDate, oldTimeslot, oldSeatID, newDate, newTimeslot, newSeatID, userID, isAnonymous });

  try {
      // Check if the new seat is the same as the old seat
      if (oldDate === newDate && oldTimeslot === newTimeslot && oldSeatID === newSeatID) {
          const seat = await Seat.findOne({ seatID: oldSeatID, date: oldDate, time: oldTimeslot, userID });
          console.log('Same seat being updated:', seat);

          if (seat) {
              seat.isAnonymous = isAnonymous;
              await seat.save();
              console.log('Reservation updated successfully for the same seat:', seat);
              return res.json({ success: true });
          } else {
              return res.status(404).json({ success: false, message: 'Seat not found or user not authorized to update this reservation' });
          }
      }

      // Check availability and reserve the new seat
      const newSeat = await Seat.findOne({ seatID: newSeatID, date: newDate, time: newTimeslot });
      console.log('New seat fetched:', newSeat);

      if (!newSeat) {
          return res.status(404).json({ success: false, message: 'New seat not found' });
      }

      if (!newSeat.isAvailable) {
          return res.status(400).json({ success: false, message: 'New seat is already reserved' });
      }

      newSeat.isAvailable = false;
      newSeat.userID = userID;
      newSeat.isAnonymous = isAnonymous;
      await newSeat.save();
      console.log('New seat reserved successfully:', newSeat);

      // Cancel the old reservation
      const oldSeat = await Seat.findOne({ seatID: oldSeatID, date: oldDate, time: oldTimeslot, userID });
      console.log('Old seat fetched:', oldSeat);

      if (oldSeat) {
          oldSeat.isAvailable = true;
          oldSeat.userID = null;
          oldSeat.isAnonymous = true;
          await oldSeat.save();
          console.log('Old reservation cancelled successfully:', oldSeat);
          res.json({ success: true });
      } else {
          res.json({ success: false, message: 'Old seat not found or user not authorized to cancel this reservation' });
      }
  } catch (error) {
      console.error('Server error:', error);
      res.status(500).send('Server error');
  }
});

app.get('/api/searchUser', async (req, res) => {
  const { userID } = req.query;
  try {
      const user = await User.findOne({ userID });
      if (user) {
          res.json(user);
      } else {
          res.status(404).json({ message: 'User not found' });
      }
  } catch (error) {
      console.error('Error fetching user:', error);
      res.status(500).send('Server error');
  }
});

app.post('/api/bookReservation', async (req, res) => {
    const { userID, date, time, seatID, building, isAnonymous } = req.body;
    console.log('Book seat request received with:', { userID, date, time, seatID, building, isAnonymous });
  
    try {
      // Check if the seat exists
      const seat = await Seat.findOne({ seatID, date, time });
      console.log('Seat fetched:', seat);
  
      if (!seat) {
        return res.status(404).json({ success: false, message: 'Seat not found' });
      }
  
      if (!seat.isAvailable) {
        return res.status(400).json({ success: false, message: 'Seat is already reserved' });
      }
  
      // Book the seat
      seat.isAvailable = false;
      seat.userID = userID;
      seat.isAnonymous = isAnonymous;
      await seat.save();
      console.log('Seat booked successfully:', seat);
  
      res.json({ success: true });
    } catch (error) {
      console.error('Server error:', error);
      res.status(500).send('Server error');
    }
  });

app.get('/otherprofile', function (req, res) {
  res.sendFile(__dirname + "/otherprofile.html");
});

app.get('/usersearch', function (req, res) {
  res.sendFile(__dirname + "/usersearch.html");
});

app.post('/submit-student-data', function (req, res) {
  var name = req.body.firstName + " " + req.body.lastName;
  res.send(name + " obtained");
});
app.post("/change-password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.session.userId); // or however you're tracking session

  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match) return res.json({ success: false });

  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  await user.save();

  res.json({ success: true });
});

const buildings = {
  'Br. Andrew Gonzales': 40,
  'Gokongwei': 20,
  'Velasco': 15
};

const timeslots = [
  '7:30-8:00', '8:15-8:45', '9:00-9:30', '9:45-10:15',
  '10:30-11:00', '11:15-11:45', '12:00-12:30', '12:45-13:15',
  '13:30-14:00', '14:15-14:45', '15:00-15:30', '15:45-16:15',
  '16:30-17:00'
];

async function populateSeats() {
  const startDate = new Date();
  const endDate = new Date();
  endDate.setDate(startDate.getDate() + 7);

  for (let date = new Date(startDate); date <= endDate; date.setDate(date.getDate() + 1)) {
    const dateString = date.toISOString().split('T')[0];

    for (const building in buildings) {
      const seatCount = buildings[building];

      for (const timeslot of timeslots) {
        for (let seatNumber = 1; seatNumber <= seatCount; seatNumber++) {
          const seatID = `${building}-${seatNumber}`;
          const existingSeat = await Seat.findOne({ seatID, date: dateString, time: timeslot });

          if (!existingSeat) {
            const seat = new Seat({
              seatID,
              date: dateString,
              time: timeslot,
              building,
              isAvailable: true
            });

            await seat.save();
          }
        }
      }
    }
  }

  console.log('Seats populated');
}

// Uncomment the following line to run the function to populate seats
// populateSeats();

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
