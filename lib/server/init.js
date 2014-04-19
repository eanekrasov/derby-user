var credential = require('credential')
  , passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;

module.exports = function (app, options) {
  if (!options.config) options.config = {};
  if (!options.config.usernameField) options.config.usernameField = 'usernameOrEmail';
  options.config.passReqToCallback = true;

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(userId, done) {
    done(null, {id: userId});
  });

  passport.use(new LocalStrategy(options.config,
    function(req, usernameOrEmail, password, done) {
      var model = req.getModel();
      var $query = !~usernameOrEmail.indexOf('@')
        ? model.query('users', {'local.username': usernameOrEmail})
        : model.query('auth', {'local.email.value': usernameOrEmail});

      $query.fetch(function (err) {
        if (err) return done(err);
        var user = $query.get()[0];
        if (!user) return done(null, false, {error: 'not found'});
        var $private = model.at('auth.' + user.id);
        $private.fetch(function (err) {
          if (err) return done(err);
          var hashedPassword = $private.get('local.password.hash');
          credential.verify(hashedPassword, password, function (err, valid) {
            if (err) return done(err);
            if (!valid) return done(null, false, {error: 'invalid password'});
            $private.del('local.password.token', function () {
              done(null, {id: user.id});
            });
          });
        });
      });
    }
  ));

  app.use(passport.initialize());
  app.use(passport.session());

  return function () {
    return function (req, res, next) {
      if (req.headers['phonegap']) return next();

      var model = req.getModel()
        , userId = req.session.user && req.session.user.id;

      if (!userId) {
        userId = model.id();
        model.add('auth', {id: userId});
        model.add('users', {id: userId, created: new Date(), isRegistered: false});
        req.session.user = {id: userId};
      }

      model.set('_session.user.id', userId);
      next();
    };
  };
};