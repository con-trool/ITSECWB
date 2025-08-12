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
const Log = require('./database/models/Log');
const path = require('path');
const bodyParser = require('body-parser');
const hbs = require('hbs');
const {isTechnician, isAdmin } = require('./auth');

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
hbs.registerHelper('json', function (context) {
  return JSON.stringify(context, null, 2);
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

function formatManilaString(input) {
  const d = new Date(input);
  if (isNaN(d)) return '';

  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Manila',
    weekday: 'short',   // Mon
    month: 'short',     // Aug
    day: '2-digit',     // 04
    year: 'numeric',    // 2025
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).formatToParts(d).reduce((acc, p) => {
    acc[p.type] = p.value;
    return acc;
  }, {});

  // "Mon Aug 04 2025 13:34:11"
  return `${parts.weekday} ${parts.month} ${parts.day} ${parts.year} ${parts.hour}:${parts.minute}:${parts.second}`;
}

app.get('/menu', allowGuest, async (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    let user;
    if (req.isGuest) {
      user = { userID: 1, isTechnician: false, name: 'Guest' };
      console.log('Accessing menu as guest');
    } else {
      user = await User.findById(req.session.userId);
      if (!user) return res.redirect('/login');
    }

    const userId = user.userID;
    const isTechnician = user.isTechnician;

    // pull from session
    const raw = req.session.lastLoginAttempt || null;

    // build object with preformatted Manila time
    const lastLoginInfo = raw ? {
      ...raw,
      // keep original date for conditionals
      date: raw.date,
      // add preformatted string (Asia/Manila)
      formattedDate: formatManilaString(raw.date)
    } : null;

    // clear after displaying once
    delete req.session.lastLoginAttempt;

    res.render('menu', {
      userId,
      isTechnician,
      isGuest: req.isGuest,
      lastLoginInfo
    });
  } catch (error) {
    console.error('Error fetching user data:', {
      message: error.message,
      stack: error.stack
    });
    next(error);
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
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
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
    next(error);
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
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
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

app.post('/login', async (req, res, next) => {
  const { email, password, rememberMe } = req.body;

  try {
    const user = await User.findOne({ username: email });

    if (!user) {
      await Log.create({
        userID: 0,
        role: 'unknown',
        action: 'login',
        details: `Login failed for unknown email: ${email}`,
        status: 'failure'
      });
      return res.render('login', {
        error: 'Invalid email or password.',
        credentials: { email, password }
      });
    }

    if (typeof user.failedLoginAttempts !== 'number') user.failedLoginAttempts = 0;
    if (!user.lockUntil) user.lockUntil = null;

    if (user.lockUntil && user.lockUntil > Date.now()) {
      await Log.create({
        userID: user.userID,
        role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
        action: 'login',
        details: `Attempted login while locked out: ${email}`,
        status: 'failure'
      });
      return res.render('login', {
        error: 'Your account is temporarily locked. Please try again later.',
        credentials: { email, password }
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      // ❌ Failed login → record attempt + false
      user.lastLoginAttempt = new Date();
      user.lastLoginSuccess = false;

      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 min
        await user.save();

        await Log.create({
          userID: user.userID,
          role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
          action: 'login',
          details: `Account locked due to too many failed attempts.`,
          status: 'failure'
        });

        return res.render('login', {
          error: 'Account locked due to too many failed attempts. Please try again later.',
          credentials: { email, password }
        });
      }

      await user.save();

      await Log.create({
        userID: user.userID,
        role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
        action: 'login',
        details: `Incorrect password for ${email}`,
        status: 'failure'
      });

      return res.render('login', {
        error: 'Invalid email or password.',
        credentials: { email, password }
      });
    }

    // Successful login → DO NOT touch lastLoginAttempt/lastLoginSuccess here
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // set session
    req.session.userId = user._id.toString();
    req.session.isTechnician = user.isTechnician;
    req.session.isAdmin = user.isAdmin;
    req.session.user = {
      _id: user._id,
      name: user.name,
      username: user.username,
      isTechnician: user.isTechnician,
      isAdmin: user.isAdmin,
      userID: user.userID,
      image: user.image,
      college: user.college,
      program: user.program,
      description: user.description
    };

    // optional: keep this if you still want to show prior attempt result in the session
    req.session.lastLoginAttempt = {
      date: user.lastLoginAttempt,
      success: user.lastLoginSuccess
    };

    if (rememberMe) {
      // ⚠️ consider not storing plaintext password here
      res.cookie('rememberMe', { email, password }, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true
      });
    } else {
      res.clearCookie('rememberMe');
    }

    await Log.create({
      userID: user.userID,
      role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
      action: 'login',
      details: `Successful login for ${email}`,
      status: 'success'
    });

    if (user.isAdmin) return res.redirect('/admin');
    if (user.isTechnician) return res.redirect('/technicianpage');
    return res.redirect('/menu');

  } catch (error) {
    console.error('Login error:', error);
    await Log.create({
      userID: 0,
      role: 'student',
      action: 'login',
      details: `Unhandled error during login: ${error.message}`,
      status: 'failure'
    });
    next(error);
  }
});


app.get('/technicianpage', isAuthenticated, isTechnician, async (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const currentUser = await User.findById(req.session.userId).exec();
    const seats = await Seat.find({ isAvailable: false }).exec();
    const users = await User.find({}).exec();

    const usersMap = users.reduce((map, user) => {
      if (user.userID) map[user.userID.toString()] = user;
      return map;
    }, {});

    const lastLoginInfo = currentUser ? {
      date: currentUser.lastLoginAttempt || null, // keep raw for conditionals
      formattedDate: currentUser.lastLoginAttempt
        ? formatManilaString(currentUser.lastLoginAttempt)
        : '',
      success: currentUser.lastLoginSuccess
    } : null;

    res.render('technicianpage', {
      user: req.session.user,
      seats,
      users: usersMap,
      lastLoginInfo
    });
  } catch (error) {
    console.error('Error fetching reservations:', error);
    next(error);
  }
});


app.get('/admin', isAuthenticated, isAdmin, async (req, res, next) =>{
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const currentUser = await User.findById(req.session.userId).exec();
    const seats = await Seat.find({ isAvailable: false }).exec();
    const users = await User.find({}).exec();

    const usersMap = users.reduce((map, user) => {
      if (user.userID) map[user.userID.toString()] = user;
      return map;
    }, {});

    const lastLoginInfo = currentUser ? {
      date: currentUser.lastLoginAttempt || null,
      formattedDate: currentUser.lastLoginAttempt
        ? formatManilaString(currentUser.lastLoginAttempt)
        : '',
      success: currentUser.lastLoginSuccess
    } : null;

    res.render('admin', {
      user: req.session.user,
      seats,
      users: usersMap,
      lastLoginInfo
    });
  } catch (error) {
    console.error('Error fetching reservations:', error);
    next(error);
  }
});


app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) =>{
   res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  try {
    const users = await User.find();
    res.render('admin_users', { users });
  } catch (err) {
    console.error('Error loading users:', err);
    next(error);
  }
});

// Show logs (admin access)
app.get('/admin/logs', isAuthenticated, isAdmin, async (req, res) => {
   res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
   try {
    const logs = await Log.find().sort({ timestamp: -1 }).lean();

    logs.forEach(log => {
      // Format timestamp to: "Mon Aug 04 2025 13:34:11"
      const dateObj = new Date(log.timestamp);
      log.timestampFormatted = dateObj.toDateString() + ' ' + dateObj.toTimeString().split(' ')[0];

      // Optional: stringify details if object
      if (typeof log.details === 'object') {
        log.details = JSON.stringify(log.details);
      }
    });

    res.render('admin_logs', { logs });
  } catch (error) {
    console.error("Error loading logs:", error);
    res.status(500).send("Failed to load logs.");
  }
});

app.post('/admin/promote', isAuthenticated, isAdmin, async (req, res) => {
  const { userId } = req.body;
  const actingUser = req.session.user;

  // Extract acting user's numeric ID and role
  const actingUserID = actingUser?.userID || 0;
  const actingRole = 'admin';

  try {
    const userToPromote = await User.findById(userId);

    if (!userToPromote) {
      // Log failed attempt due to user not found
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'promote',
        details: `Promotion failed - technician not found (ID: ${userId})`,
        status: 'failure'
      });

      return res.status(404).json({ success: false, message: 'User not found' });
    }

    userToPromote.isAdmin = true;
    await userToPromote.save();

    // Log successful promotion
    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'promote',
      details: `Promoted technician with ID ${userToPromote.userID} to admin`,
      status: 'success'
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Promotion error:', error);

    // Log any unhandled server error
    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'promote',
      details: `Unhandled error during promotion: ${error.message}`,
      status: 'failure'
    });

    res.status(500).json({ success: false });
  }
});


app.get('/register', function (req, res) {
  res.render('register');
});

// Put this near your routes
function lengthValidatorJson(req, res, next) {
  const email = (req.body.email ?? '').toString().trim();
  const password = (req.body.password ?? '').toString();
  const securityAnswer = (req.body.securityAnswer ?? '').toString().trim();
  const cpLen = s => [...s].length;

  if (cpLen(email) > 254)
    return res.status(400).json({ success: false, message: 'Email must be 254 characters or fewer.' });
  if (cpLen(password) > 128)
    return res.status(400).json({ success: false, message: 'Password must be 128 characters or fewer.' });
  if (securityAnswer && cpLen(securityAnswer) > 128)
    return res.status(400).json({ success: false, message: 'Security answer must be 128 characters or fewer.' });

  req.body.email = email; // normalized for downstream
  next();
}

app.post('/register', lengthValidatorJson, async (req, res) => {
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
      await Log.create({
        userID: 0,
        role: 'student',
        action: 'register',
        details: 'Missing required fields',
        status: 'failure'
      });
      return res.send(`<script>alert('All fields are required.'); window.history.back();</script>`);
    }

    if (!email.endsWith('@dlsu.edu.ph')) {
      await Log.create({
        userID: 0,
        role: 'student',
        action: 'register',
        details: `Invalid email domain: ${email}`,
        status: 'failure'
      });
      return res.send(`<script>alert('Email must end with @dlsu.edu.ph'); window.history.back();</script>`);
    }

    if (password !== confirmPassword) {
      await Log.create({
        userID: 0,
        role: 'student',
        action: 'register',
        details: `Password mismatch for email: ${email}`,
        status: 'failure'
      });
      return res.send(`<script>alert('Passwords do not match.'); window.history.back();</script>`);
    }

    const existingUser = await User.findOne({ username: email });
    if (existingUser) {
      await Log.create({
        userID: 0,
        role: 'student',
        action: 'register',
        details: `Duplicate registration attempt for email: ${email}`,
        status: 'failure'
      });
      return res.send(`<script>alert('Unable to register with provided information.'); window.history.back();</script>`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const localPart = email.split('@')[0];
    const name = localPart
      .split('_')
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');

    const userID = Date.now();
    const newUser = new User({
      username: email,
      password: hashedPassword,
      name,
      securityQuestion,
      securityAnswer,
      isTechnician: isTechnician === 'true',
      userID,
      passwordHistory: [hashedPassword]
    });

    await newUser.save();
    console.log("New user saved:", newUser);

    await Log.create({
      userID,
      role: isTechnician === 'true' ? 'technician' : 'student',
      action: 'register',
      details: `New user registered: ${email}`,
      status: 'success'
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Error registering new user:", error);
    await Log.create({
      userID: 0,
      role: 'student',
      action: 'register',
      details: `Unhandled error: ${error.message}`,
      status: 'failure'
    });
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
    if (!user) {
      await Log.create({
        userID: 0,
        role: 'unknown',
        action: 'change_password',
        details: `Password reset failed - user not found for email: ${email}`,
        status: 'failure'
      });
      return res.json({ success: false });
    }

    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours

    if (user.lastPasswordChange > oneDayAgo) {
      await Log.create({
        userID: user.userID,
        role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
        action: 'change_password',
        details: `Password reset blocked - attempted before 24-hour cooldown.`,
        status: 'failure'
      });

      return res.json({
        success: false,
        message: "Password was recently changed. You can only change your password once every 24 hours."
      });
    }

    // Check for password reuse
    for (const oldHashed of user.passwordHistory) {
      const isReused = await bcrypt.compare(newPassword, oldHashed);
      if (isReused) {
        await Log.create({
          userID: user.userID,
          role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
          action: 'change_password',
          details: `Password reset blocked - reused password detected.`,
          status: 'failure'
        });

        return res.json({
          success: false,
          message: "This password has already been used. Please create a unique password."
        });
      }
    }

    // Hash and save new password
    const hashed = await bcrypt.hash(newPassword, 10);

    user.password = hashed;
    user.lastPasswordChange = now;
    user.passwordHistory.push(hashed);

    // Keep only last 5 passwords
    if (user.passwordHistory.length > 5) {
      user.passwordHistory = user.passwordHistory.slice(-5);
    }

    await user.save();

    await Log.create({
      userID: user.userID,
      role: user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student',
      action: 'change_password',
      details: `Password reset successfully via forgot-password route.`,
      status: 'success'
    });

    res.json({ success: true });

  } catch (error) {
    console.error("Error resetting password:", error);

    await Log.create({
      userID: 0,
      role: 'unknown',
      action: 'change_password',
      details: `Unhandled error during password reset: ${error.message}`,
      status: 'failure'
    });

    res.status(500).send("Internal server error");
  }
});


// Logout route
function getUserRole(session) {
  if (session?.isAdmin) return 'admin';
  if (session?.isTechnician) return 'technician';
  return 'student';
}

const util = require('util');

function getUserRole(session) {
  if (session?.isAdmin) return 'admin';
  if (session?.isTechnician) return 'technician';
  return 'student';
}

app.get('/logout', async (req, res) => {
  const userID = req.session.user?.userID || 0;
  const role = getUserRole(req.session);

  const destroySession = util.promisify(req.session.destroy).bind(req.session);

  try {
    // Overwrite fields on successful session logout
    const mongoId = req.session.userId;
    if (mongoId) {
      try {
        const user = await User.findById(mongoId);
        if (user) {
          user.lastLoginAttempt = new Date(); // overwrite at logout time
          user.lastLoginSuccess = true;       // mark that the last completed session was successful
          await user.save();
        }
      } catch (e) {
        console.error('Failed to update last login fields on logout:', e);
      }
    }

    await destroySession();
    res.clearCookie('connect.sid');

    await Log.create({
      userID,
      role,
      action: 'logout',
      details: `User logged out successfully.`,
      status: 'success'
    });

    res.redirect('/login');
  } catch (err) {
    console.error("Error during logout:", err);

    await Log.create({
      userID,
      role,
      action: 'logout',
      details: `Logout failed: ${err.message}`,
      status: 'failure'
    });

    res.status(500).send('Logout failed');
  }
});

app.get('/userprofile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('userprofile', { user });
  } catch (error) {
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
  }
});

app.get('/edituserpage', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('edituserpage', { user });
  } catch (error) {
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
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
    next(error);
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
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
  }
});

app.get('/api/seats', async (req, res) => {
  try {
    const { date, timeslot, building } = req.query;
    const seats = await Seat.find({ date, time: timeslot, building });
    res.json(seats);
  } catch (error) {
    console.error('Error fetching seats:', error);
    next(error);
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
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });
    next(error);
  }
});

app.post('/api/reserve', isAuthenticated, async (req, res) => {
  const { date, timeslot, seatID, isAnonymous } = req.body;
  const currentUser = req.session.user;

  // Extract student info from session
  const actingUserID = currentUser?.userID || 0;
  const actingRole = 'student';

  console.log('Student reservation request:', {
    date, timeslot, seatID, isAnonymous, actingUserID
  });

  // Deny access if the user is an admin or technician
  if (currentUser.isAdmin || currentUser.isTechnician) {
    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'booking',
      details: `Unauthorized reservation attempt by ${currentUser.isAdmin ? 'admin' : 'technician'} (userID: ${actingUserID})`,
      status: 'failure'
    });

    return res.status(403).json({ success: false, message: 'Only students can reserve seats via this route' });
  }

  try {
    const seat = await Seat.findOne({ seatID, date, time: timeslot });
    console.log('Fetched seat from database:', seat);

    if (!seat) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Reservation failed - seat not found. seatID: ${seatID}, date: ${date}, time: ${timeslot}`,
        status: 'failure'
      });

      return res.status(404).json({ success: false, message: 'Seat not found' });
    }

    if (!seat.isAvailable) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Reservation failed - seat already reserved. seatID: ${seatID}, date: ${date}, time: ${timeslot}`,
        status: 'failure'
      });

      return res.status(400).json({ success: false, message: 'Seat is already reserved' });
    }

    // Reserve seat
    seat.isAvailable = false;
    seat.userID = actingUserID;
    seat.isAnonymous = isAnonymous;

    await seat.save();
    console.log('Seat reserved successfully:', seat);

    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'booking',
      details: `Student reserved seatID: ${seatID} on ${date} at ${timeslot}`,
      status: 'success'
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error reserving seat:', error);

    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'booking',
      details: `Unhandled error during reservation: ${error.message}`,
      status: 'failure'
    });

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
    console.error('Error fetching user data:', { //for 2.3.1
      message: error.message,
      stack: error.stack
    });

    next(error);
  }
});

app.get('/api/users', async (req, res) => {
  const { query, college, degree } = req.query;

  try {
    const filter = { isAdmin: false || null, isTechnician: false ,  userID: { $ne: 1 }   };

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
    next(error);
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
    next(error);
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

app.post('/api/cancel', isAuthenticated, async (req, res, next) => {
  const { date, timeslot, seatID, userID: bodyUserID } = req.body;
  const currentUser = req.session.user;

  const actingRole = currentUser?.isAdmin
    ? 'admin'
    : currentUser?.isTechnician
      ? 'technician'
      : 'student';

  // normalize ids to strings
  const sessionUserID   = String(currentUser?.userID ?? '0');
  const requestedUserID = bodyUserID != null ? String(bodyUserID) : null;
  const isPrivileged    = !!(currentUser?.isAdmin || currentUser?.isTechnician);

  // who is the action for?
  const targetUserID = isPrivileged ? (requestedUserID || sessionUserID) : sessionUserID;

  // students trying to cancel for someone else?
  if (!isPrivileged && requestedUserID && requestedUserID !== sessionUserID) {
    await Log.create({
      userID: sessionUserID,
      role: actingRole,
      action: 'cancel_booking',
      details: `Unauthorized cancel attempt by student. Target userID: ${requestedUserID}`,
      status: 'failure'
    });
    return res.status(403).json({ success: false, message: 'Unauthorized to cancel this reservation' });
  }

  console.log(`Cancel request by ${actingRole} (${sessionUserID}) for reservation of userID: ${targetUserID}`, {
    seatID, date, timeslot
  });

  try {
    // must match the user's reservation
    const query = { seatID, date, time: timeslot, userID: targetUserID };
    const seat = await Seat.findOne(query);

    if (!seat) {
      // fetch what exists at that key to help debugging
      const existing = await Seat.findOne({ seatID, date, time: timeslot });
      const snapshot = existing ? {
        seatID: existing.seatID,
        date: existing.date,
        time: existing.time,
        isAvailable: existing.isAvailable,
        userID: existing.userID ?? null
      } : null;

      await Log.create({
        userID: sessionUserID,
        role: actingRole,
        action: 'cancel_booking',
        details: `Cancel failed - Seat not found for user or unauthorized. Target userID: ${targetUserID}, seatID: ${seatID}, date: ${date}, time: ${timeslot}. Seat snapshot: ${JSON.stringify(snapshot)}`,
        status: 'failure'
      });

      return res.status(404).json({ success: false, message: 'Seat not found for this user' });
    }

    // perform cancel
    seat.isAvailable = true;
    seat.userID = null;
    seat.isAnonymous = false; // keep your current behavior; set true if you prefer
    await seat.save();

    await Log.create({
      userID: sessionUserID,
      role: actingRole,
      action: 'cancel_booking',
      details: `${actingRole} canceled reservation for userID: ${targetUserID}, seatID: ${seatID}, date: ${date}, time: ${timeslot}`,
      status: 'success'
    });

    return res.json({ success: true });

  } catch (error) {
    console.error('Cancel reservation error:', error);
    await Log.create({
      userID: sessionUserID,
      role: actingRole,
      action: 'cancel_booking',
      details: `Unhandled error during cancel_booking for userID: ${targetUserID} - ${error.message}`,
      status: 'failure'
    });
    return next(error);
  }
});

app.post('/api/editReservation', isAuthenticated, async (req, res, next) => {
  const {
    oldDate, oldTimeslot, oldSeatID,
    newDate, newTimeslot, newSeatID,
    userID: bodyUserID,
    isAnonymous
  } = req.body;

  const currentUser = req.session.user; // logged-in user
  const actingRole = currentUser.isAdmin
    ? 'admin'
    : currentUser.isTechnician
      ? 'technician'
      : 'student';

  // Normalize IDs to avoid 123 !== "123" surprises
  const sessionUserID = String(currentUser.userID);
  const requestedUserID = bodyUserID != null ? String(bodyUserID) : null;

  const isPrivileged = !!(currentUser.isAdmin || currentUser.isTechnician);

  // Who is the action for?
  const targetUserID = isPrivileged
    ? (requestedUserID || sessionUserID)
    : sessionUserID;

  // Students trying to act for someone else?
  if (!isPrivileged && requestedUserID && requestedUserID !== sessionUserID) {
    await Log.create({
      userID: sessionUserID,
      role: actingRole,
      action: 'edit_booking',
      details: `Unauthorized attempt to edit another user's reservation (Target User: ${requestedUserID})`,
      status: 'failure'
    });
    return res.status(403).json({ success: false, message: 'Unauthorized to edit this reservation' });
  }

  console.log(`Edit reservation request by ${actingRole} ${sessionUserID} for user ${targetUserID}`, {
    oldDate, oldTimeslot, oldSeatID, newDate, newTimeslot, newSeatID, isAnonymous
  });

  try {
    // CASE 1: Just updating anonymity flag
    if (oldDate === newDate && oldTimeslot === newTimeslot && oldSeatID === newSeatID) {
      const seat = await Seat.findOne({
        seatID: oldSeatID,
        date: oldDate,
        time: oldTimeslot,
        userID: targetUserID
      });

      if (!seat) {
        await Log.create({
          userID: sessionUserID,
          role: actingRole,
          action: 'edit_booking',
          details: `Seat not found or unauthorized to update (User: ${targetUserID}, SeatID: ${oldSeatID})`,
          status: 'failure'
        });
        return res.status(404).json({ success: false, message: 'Seat not found or unauthorized' });
      }

      seat.isAnonymous = !!isAnonymous;
      await seat.save();

      await Log.create({
        userID: sessionUserID,
        role: actingRole,
        action: 'edit_booking',
        details: `${actingRole} updated anonymity for reservation (User: ${targetUserID}, SeatID: ${oldSeatID})`,
        status: 'success'
      });

      return res.json({ success: true });
    }

    // CASE 2: Changing to a different seat
    const newSeat = await Seat.findOne({ seatID: newSeatID, date: newDate, time: newTimeslot });

if (!newSeat || !newSeat.isAvailable) {
  const seatSnapshot = newSeat ? {
    seatID: newSeat.seatID,
    date: newSeat.date,
    time: newSeat.time,
    isAvailable: newSeat.isAvailable,
    userID: newSeat.userID ?? null
  } : null;

  await Log.create({
    userID: sessionUserID,
    role: actingRole,
    action: 'edit_booking',
    details: `Failed seat change for user ${targetUserID}. New seat invalid or already reserved. Seat snapshot: ${JSON.stringify(seatSnapshot)}`,
    status: 'failure'
  });

  return res.status(400).json({ success: false, message: 'New seat not available' });
}

    // Reserve the new seat
    newSeat.isAvailable = false;
    newSeat.userID = targetUserID;
    newSeat.isAnonymous = !!isAnonymous;
    await newSeat.save();

    // Release old seat (only the caller's)
    const oldSeat = await Seat.findOne({ seatID: oldSeatID, date: oldDate, time: oldTimeslot, userID: targetUserID });
    if (oldSeat) {
      oldSeat.isAvailable = true;
      oldSeat.userID = null;
      oldSeat.isAnonymous = true;
      await oldSeat.save();
    }

    await Log.create({
      userID: sessionUserID,
      role: actingRole,
      action: 'edit_booking',
      details: `${actingRole} changed reservation for user ${targetUserID} from ${oldSeatID} to ${newSeatID}`,
      status: 'success'
    });

    return res.json({ success: true });
  } catch (error) {
    console.error('Edit reservation error:', error);
    await Log.create({
      userID: sessionUserID || '0',
      role: actingRole,
      action: 'edit_booking',
      details: `Unhandled error during edit_booking for user ${targetUserID}: ${error.message}`,
      status: 'failure'
    });
    next(error);
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
      next(error);
  }
});

app.post('/api/bookReservation', async (req, res, next) => {
  const { userID, date, time, seatID, building, isAnonymous } = req.body;
  const currentUser = req.session.user; // The logged-in user performing the action

  const actingUserID = currentUser?.userID || 0;
  const actingRole = currentUser?.isAdmin
    ? 'admin'
    : currentUser?.isTechnician
      ? 'technician'
      : 'student';

  console.log(`Booking request by ${actingRole} (ID: ${actingUserID}) for student ${userID}`, {
    date, time, seatID, building, isAnonymous
  });

  try {
    // Students can only book for themselves
    if (actingRole === 'student' && userID !== actingUserID) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Unauthorized booking attempt by student for another user (Target: ${userID})`,
        status: 'failure'
      });

      return res.status(403).json({ success: false, message: 'Unauthorized to book for another user' });
    }

    // Ensure the target user exists
    const targetUser = await User.findOne({ userID });
    if (!targetUser) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Booking failed - target user not found (Target: ${userID})`,
        status: 'failure'
      });

      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const seat = await Seat.findOne({ seatID, date, time });
    console.log('Seat fetched:', seat);

    if (!seat) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Booking failed - seat not found. seatID: ${seatID}, date: ${date}, time: ${time}, for user: ${userID}`,
        status: 'failure'
      });

      return res.status(404).json({ success: false, message: 'Seat not found' });
    }

    if (!seat.isAvailable) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'booking',
        details: `Booking failed - seat already reserved. seatID: ${seatID}, date: ${date}, time: ${time}, for user: ${userID}`,
        status: 'failure'
      });

      return res.status(400).json({ success: false, message: 'Seat is already reserved' });
    }

    // Book seat
    seat.isAvailable = false;
    seat.userID = userID;
    seat.isAnonymous = isAnonymous;
    await seat.save();
    console.log('Seat booked successfully:', seat);

    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'booking',
      details: `${actingRole} booked seatID: ${seatID} on ${date} at ${time} in ${building} for user: ${userID}`,
      status: 'success'
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Booking error:', error);

    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'booking',
      details: `Unhandled error during booking for user ${userID}: ${error.message}`,
      status: 'failure'
    });

    next(error);
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
  const user = await User.findById(req.session.userId);

  if (!user) {
    return res.status(401).json({ success: false, message: "Not authenticated" });
  }

  const actingUserID = user.userID;
  const actingRole = user.isAdmin ? 'admin' : user.isTechnician ? 'technician' : 'student';

  try {
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'change_password',
        details: 'Failed password change attempt - incorrect current password',
        status: 'failure'
      });
      return res.json({ success: false, message: "Incorrect current password." });
    }

    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    if (user.lastPasswordChange && user.lastPasswordChange > oneDayAgo) {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'change_password',
        details: 'Password change blocked - cooldown period not met (24h)',
        status: 'failure'
      });
      return res.json({
        success: false,
        message: "You can only change your password once every 24 hours."
      });
    }

    // Reuse check
    if (user.passwordHistory?.length) {
      for (const oldHash of user.passwordHistory) {
        if (await bcrypt.compare(newPassword, oldHash)) {
          await Log.create({
            userID: actingUserID,
            role: actingRole,
            action: 'change_password',
            details: 'Password change blocked - reused password detected',
            status: 'failure'
          });
          return res.json({
            success: false,
            message: "This password has already been used. Please choose a unique password."
          });
        }
      }
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    user.password = hashed;
    user.lastPasswordChange = now;
    user.passwordHistory = user.passwordHistory || [];
    user.passwordHistory.push(hashed);
    if (user.passwordHistory.length > 5) {
      user.passwordHistory = user.passwordHistory.slice(-5);
    }

    await user.save();

    await Log.create({
      userID: actingUserID,
      role: actingRole,
      action: 'change_password',
      details: 'Password changed successfully',
      status: 'success'
    });

    // Immediately log the user out
    const destroySession = util.promisify(req.session.destroy).bind(req.session);
    try {
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'logout',
        details: 'Auto-logout after password change',
        status: 'success'
      });

      await destroySession();
      res.clearCookie('connect.sid'); // adjust if you use a custom cookie name

      return res.json({
        success: true,
        loggedOut: true,
        redirect: '/login',
        message: 'Password changed. You have been logged out for security.'
      });
    } catch (logoutErr) {
      console.error('Session destroy failed after password change:', logoutErr);
      await Log.create({
        userID: actingUserID,
        role: actingRole,
        action: 'logout',
        details: `Auto-logout failed after password change: ${logoutErr.message}`,
        status: 'failure'
      });
      // Password is changed, but session still alive; tell client to redirect anyway
      return res.json({
        success: true,
        loggedOut: false,
        redirect: '/login',
        message: 'Password changed. Please log in again.'
      });
    }

  } catch (error) {
    console.error('Change password error:', error);
    await Log.create({
      userID: actingUserID || 0,
      role: actingRole || 'student',
      action: 'change_password',
      details: `Unhandled error during password change: ${error.message}`,
      status: 'failure'
    });
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
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

/* uncomment to test error 500 and run this in browser http://localhost:5000/test-error
                      error 404 - http://localhost:5000/nonexistentroute

app.get('/test-error', (req, res) => {
  throw new Error("Forced server error test");
});*/

//custom error
app.use((req, res, next) => {
res.status(404);

  // If it's an API call or JSON request
  if (req.originalUrl.startsWith('/api') || req.headers.accept?.includes('application/json')) {
    return res.json({ error: 'Not found' });
  }

  // Render 404 page
  res.render('errors/404');
});


// Global error handler — must be the last middleware
app.use((err, req, res, next) => {
  // Use the status code from AppError or default to 500
  const status = err.status || 500;

  console.error("Unhandled error:", err);

  res.status(status);

  // API/JSON requests
  if (req.originalUrl.startsWith('/api') || req.headers.accept?.includes('application/json')) {
    return res.json({
      message: err.message || 'Internal server error',
    });
  }

  // Render appropriate custom error page
  if (status === 404) {
    return res.render('errors/404');
  }

  res.render('errors/500');
});

