//auth.js
const Log = require('./database/models/Log.js'); 

function isAdmin(req, res, next) {
  if (req.session?.user?.isAdmin === true) {
    return next();
  }

  const actingUser = req.session?.user || {};
  const actingUserID = actingUser.userID || 0;

  // Log unauthorized access attempt
  Log.create({
    userID: actingUserID,
    role: actingUser.isTechnician ? 'technician' : 'student',
    action: 'access_control',
    details: 'Unauthorized attempt to access admin-only page',
    status: 'failure'
  }).catch(console.error); // Avoid crashing if logging fails

  return res.status(403).render('errors/403');
}

function isTechnician(req, res, next) {
  if (req.session?.user?.isTechnician === true) {
    return next();
  }

  const actingUser = req.session?.user || {};
  const actingUserID = actingUser.userID || 0;

  // Log unauthorized access attempt
  Log.create({
    userID: actingUserID,
    role: actingUser.isAdmin ? 'admin' : 'student',
    action: 'access_control',
    details: 'Unauthorized attempt to access technician-only page',
    status: 'failure'
  }).catch(console.error); // Prevent crash if logging fails

  return res.status(403).render('errors/403');
}

module.exports = {
  isTechnician,
  isAdmin
};
