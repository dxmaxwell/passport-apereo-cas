# passport-apero-cas

CAS authentication strategies for Passport.

Originally developed at <https://github.com/sadne/passport-cas>. 

Development continued by <https://github.com/jcu-eresearch/passport-cas.git>
to replace deprecated Express syntax and upgrade depedencies.

This repository improves over those projects by converting to TypeScript, 
and adding support for HTTP proxy configuration via http_proxy environment variable.

## Install

    $ npm install passport-apereo-cas

#### Configure Strategy

    passport.use(new (require('passport-apereo-cas').Strategy)({
      casBaseURL: 'http://www.example.com/',
      serviceBaseURL: 'http://localhost:3000'
    }, function(login, done) {
      User.findOne({login: login}, function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, {message: 'Unknown user'});
        }
        return done(null, user);
      });
    }));

#### Authenticate Requests

    passport.authenticate('cas', function (err, user, info) {
      if (err) {
        return next(err);
      }

      if (!user) {
        req.session.messages = info.message;
        return res.redirect('/');
      }

      req.logIn(user, function (err) {
        if (err) {
          return next(err);
        }

        req.session.messages = '';
        return res.redirect('/');
      });
    })

For example:

    // GET: '/cas_login'
    exports.casLogin = function(req, res, next) {
      passport.authenticate('cas', function (err, user, info) {
        if (err) {
          return next(err);
        }

        if (!user) {
          req.session.messages = info.message;
          return res.redirect('/');
        }

        req.logIn(user, function (err) {
          if (err) {
            return next(err);
          }

          req.session.messages = '';
          return res.redirect('/');
        });
      })(req, res, next);
    };

### CAS versions

## CAS 3.0 configuration
Since CAS3.0, the validation service returns a list of attributes for the authenticated user.
Here is how you can use them:

    passport.use(new (require('passport-cas').Strategy)({
      version: 'CAS3.0',
      casBaseURL: 'http://www.example.com/',
      serviceBaseURL: 'http://localhost:3000'
    }, function(profile, done) {
      var login = profile.user;

      User.findOne({login: login}, function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, {message: 'Unknown user'});
        }
        user.attributes = profile.attributes;
        return done(null, user);
      });
    }));

## CAS 2.0 configuration
CAS 2.0 will work with the CAS 3.0 configuration, but you need to set the validation endpoint.

    passport.use(new (require('passport-cas').Strategy)({
      version: 'CAS3.0',
      casBaseURL: 'http://www.example.com/',
      serviceBaseURL: 'http://localhost:3000/cas',
      validateURL: '/serviceValidate'
    }, function(profile, done) {
      var login = profile.user;
    
      User.findOne({login: login}, function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, {message: 'Unknown user'});
        }
        return done(null, user);
      });
    }));

## License

[The MIT License](http://opensource.org/licenses/MIT)
