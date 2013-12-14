var credential = require('credential')
  , moment = require('moment')
  , passport = require('passport');

module.exports = function (app, options) {
  options.tokenDuration = options.tokenDuration || 86400000;

  return function () {
    app.post('/user/signin', function (req, res, next) {
      passport.authenticate('local', function (err, user, info) {
        if (err) return res.send(500, {error: err});
        if (info) return res.send(400, info);
        if (!user) return res.send(404, {error: 'not found'});
        req.session.user = user;
        req.getModel().set('_session.user', user, function () {
          res.send({user: user});
        });
      })(req, res, next);
    });

    app.post('/user/signout', function (req, res) {
      var model = req.getModel()
        , user = model.get('_session.user');
      if (!!user) {
        model.at('users.' + user.id).fetch(function (err) {
          if (err) return res.send(500, {error: err});
          req.session.user = null;
          model.set('_session.user', null, function () {
            res.send(null);
          });
        });
      } else {
        return res.send(400, {error: 'not signed in'});
      }
    });
 
    app.post('/user/signup', function (req, res) {
      var model = req.getModel()
        , email = (req.body.email || '').trim()
        , password = req.body.password || ''
        , username = (req.body.username || '').trim()
        , user = model.get('_session.user')

      if (!!user) return res.send(400, {error: 'already registered'});
      if (!email) return res.send(400, {error: 'missing email'});
      if (!password) return res.send(400, {error: 'missing password'});
      if (!username) return res.send(400, {error: 'missing username'});

      var $query1 = model.query('users', {'username': username})
        , $query2 = model.query('users', {'email.value': email});

      model.fetch($query1, $query2,
        function (err) {
          if (err) return res.send(500, {error: err});
          var userByUsernameExists = $query1.get().length > 0
            , userByEmailExists = $query2.get().length > 0;
          if (userByEmailExists || userByUsernameExists) return res.send(400, {error: 'user exists'});
          var token = model.id();
          credential.hash(token, function (err, hashedToken) {
            if (err) return res.send(500, {error: err});
            credential.hash(password, function (err, hashedPassword) {
              if (err) return res.send(500, {error: err});
              var userData = {
                'id': token,
                'joined': new Date(),
                'username': username,
                'email': {
                  'token': { 'date': new Date(), 'hash': hashedToken },
                  'value': email,
                  'verified': false
                },
                'password': { 'hash': hashedPassword }
              };
              model.add('users', userData, function () {
                app.emit('user.signup', {req: req, userId: userData.id});
                res.send();
              });
            });
          });
        }
      );
    });

    app.post('/user/sessionize', function (req, res) {
      var model = req.getModel()
        , user = req.session.user;
      model.set('_session.user', user, function () {
        res.send({user: user});
      });
    });

    app.post('/user/changeEmail', function (req, res) {
      var model = req.getModel()
        , email = (req.body.email || '').trim()
        , $query = model.query('users', {email: email})
        , user = model.get('_session.user');
      if (!user) return res.send(400, {error: 'not signed in'});
      var $user = model.at('users.' + user.id);
      if (!email) return res.send(400, {error: 'missing email'});
      model.fetch($user, $query, function (err) {
        if (err) return res.send(500, {error: err});
        var emailExists = $query.get().length > 0;
        if (emailExists) return res.send(400, {error: 'email in use'});
        var token = model.id();
        credential.hash(token, function (err, hashedToken) {
          if (err) return res.send(500, {error: err});
          var oldEmail = $user.get('email.value');
          $user.set('email.token.date', new Date());
          $user.set('email.token.hash', hashedToken);
          $user.set('email.value', email);
          $user.set('email.verified', false, function () {
            app.emit('user.changeEmail', {token: token, userId: user.id});
          });
          if (!oldEmail) return res.send();
        });
      });
    });

    app.post('/user/changeUsername', function (req, res) {
      var model = req.getModel()
        , username = (req.body.username || '').trim()
        , user = model.get('_session.user');
      if (!user) return res.send(400, {error: 'not signed in'});
      var $query = model.query('users', {id: {$ne: user.id}, 'username': username})
        , $user = model.at('users.' + user.id);
      if (!username) return res.send(400, {error: 'missing username'});
      model.fetch($user, $query, function (err) {
        if (err) return res.send(500, {error: err});
        var usernameExists = $query.get().length > 0;
        if (usernameExists) return res.send(400, {error: 'username in use'});
        $user.set('username', username, function () {
          res.send();
        });
      });
    });

    app.post('/user/changePassword', function (req, res) {
      var model = req.getModel()
        , password = req.body.password
        , confirmPassword = req.body.confirmPassword || password
        , user = model.get('_session.user');
      if (!user) return res.send(400, {error: 'not signed in'});
      var $user = model.at('users.' + user.id);
      if (!password) return res.send(400, {error: 'missing password'});
      if (password !== confirmPassword) return res.send(400, {error: 'passwords do not match'});

      $user.fetch(function (err) {
        if (err) return res.send(500, {error: err});
        credential.hash(password, function (err, hashedPassword) {
          if (err) return res.send(500, {error: err});
          $user.set('password.hash', hashedPassword, function () {
            res.send();
          });
        });
      });
    });

    app.get('/user/confirmEmail/:token', function (req, res, next) {
      var model = req.getModel()
        , token = req.params.token
        , user = model.get('_session.user');
      if (!user.id) return next('not signed in');
      var $user = model.at('users.' + user.id);
      if (!token) return next('missing token');
      $user.fetch(function (err) {
        if (err) return next(err);
        var elapsed = moment().diff($user.get('email.token.date'));
        if (elapsed > options.tokenDuration) return next('token expired');
        var hashedToken = $user.get('email.token.hash');
        credential.verify(hashedToken, token, function (err, valid) {
          if (err) return next(err);
          if (!valid) return next('invalid token');
          $user.del('email.token');
          $user.set('email.verified', true, function () {
            res.redirect('/user/confirmedEmail');
          });
        });
      });
    });

    app.get('/user/confirmedEmail', function (req, res) {
      res.redirect('/');
    });

    app.post('/user/confirmEmail', function (req, res) {
      var model = req.getModel()
        , token = req.body.token
        , user = model.get('_session.user');

      if (!user) return res.send(400, {error: 'not signed in'});
      var $user = model.at('users.' + user.id);
      if (!token) return res.send(400, {error: 'missing token'});

      $user.fetch(function (err) {
        if (err) return res.send(500, {error: err});
        var elapsed = moment().diff($user.get('email.token.date'));
        if (elapsed > options.tokenDuration) return res.send(400, {error: 'token expired'});
        var hashedToken = $user.get('email.token.hash');
        credential.verify(hashedToken, token, function (err, valid) {
          if (err) return res.send(500, {error: err});
          $user.del('email.token');
          $user.set('email.verified', true, function () {
            res.send();
          });
        });
      });
    });

    app.post('/user/forgotPassword', function (req, res) {
      var model = req.getModel()
        , usernameOrEmail = (req.body.usernameOrEmail || '').trim()
        , $query = !~usernameOrEmail.indexOf('@')
            ? model.query('users', {'username': usernameOrEmail})
            : model.query('users', {'email.value': usernameOrEmail});

      if (!usernameOrEmail) return res.send(400, {error: 'missing username or email'});

      $query.fetch(function (err) {
        if (err) return res.send(500, {error: err});
        var user = $query.get()[0];
        if (!user) return res.send(400, {error: 'not found'});
        var $user = model.at('users.' + user.id);
        $user.fetch(function (err) {
          if (err) return res.send(500, {error: err});
          var token = model.id();
          credential.hash(token, function (err, hashedToken) {
            if (err) return res.send(500, {error: err});
            $user.set('password.token.date', new Date());
            $user.set('password.token.hash', hashedToken, function () {
              app.emit('user.forgotPassword', {token: token, userId: user.id});
              res.send();
            });
          });
        });
      });
    });

    app.post('/user/verifyEmail', function (req, res) {
      var model = req.getModel()
        , email = (req.body.email || '').trim()
        , user = model.get('_session.user');
      if (!user) return res.send(400, {error: 'not signed in'});
      var $query = model.query('users', {id: {$ne: user.id}, 'email.value': email})
        , $user = model.at('users.' + user.id);
      model.fetch($user, $query, function (err) {
        if (err) return res.send(500, {error: err});
        var user = $query.get()[0];
        if (user) return res.send(400, {error: 'email in use'});
        if (email) $user.set('email.value', email);
        var token = model.id();
        credential.hash(token, function (err, hashedToken) {
          if (err) return res.send(500, {error: err});
          $user.set('email.token.date', new Date());
          $user.set('email.token.hash', hashedToken, function () {
            app.emit('user.verifyEmail', {token: token, userId: user.id});
            res.send();
          });
        });
      });
    });

    app.post('/user/resetPassword', function (req, res, next) {
      var model = req.getModel()
        , password = req.body.password
        , confirmPassword = req.body.confirmPassword || password
        , token = req.body.token
        , userId = req.body.userId
        , $user = model.at('users.' + userId);

      if (!userId) return res.send(400, {error: 'missing user id'});
      if (!password) return res.send(400, {error: 'missing password'});
      if (password !== confirmPassword) return res.send(400, {error: 'passwords do not match'});

      $user.fetch(function (err) {
        if (err) return res.send(500, {error: err});
        var elapsed = moment().diff($user.get('password.token.date'));
        if (elapsed > options.tokenDuration) return next('token expired');
        var hashedToken = $user.get('password.token.hash');
        credential.verify(hashedToken, token, function (err, valid) {
          if (err) return res.send(500, {error: err});
          if (!valid) return res.send(400, {error: 'invalid token'});
          credential.hash(password, function (err, hashedPassword) {
            if (err) return res.send(500, {error: err});
            $user.del('password.token');
            $user.set('password.hash', hashedPassword, function () {
              res.send();
            });
          });
        });
      });
    });

    return function (req, res, next) {
      next();
    };
  };
};