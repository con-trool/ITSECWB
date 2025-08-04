//auth.js

function isAdmin(req, res, next) {
  if (req.session?.user?.isAdmin === true) {
    return next();
  }
  return res.status(403).render('errors/404');
}

function isTechnician(req, res, next) {
  if (req.session?.user?.isTechnician === true) {
    return next();
  }
  return res.status(403).render('errors/404');
}

module.exports = {
  isTechnician,
  isAdmin
};
