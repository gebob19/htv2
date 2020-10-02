const rateLimiter = require('express-rate-limit');
const User = require('../models/user');
const mail = require('../mail');
const isEmail = require('validator/lib/isEmail');
const helpers = require('../helpers');

const rateLimitResetVerification = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit up to 3 per IP
  message: { // Error json sent
    message: 'Too many requests. Please try again later.'
  }
});

module.exports = {
  attachRoute(app, recaptcha) {
    app.get('/verification/:token', rateLimitResetVerification, (req, res) => {
      const token = req.params.token;

      User.findOne({
        verification_token: token
      }, async (err, user) => {
        if (err) {
          res.status(500);
          res.send('500');
        }

        if (!user) {
          res.status(400);
          res.send('INVALID_TOKEN');
          return;
        }

        user.verified = true,
        user.verification_token = null;
        await user.save();
        res.redirect('/');
      });
    });

    app.post('/reset-verification', recaptcha.middleware.verify, (req, res) => {
      if (req.recaptcha.error) {
        res.status(400)
        res.json({
          error: true,
          code: 'INVALID_RECAPTCHA'
        });
        return
      }

      if (!req.body) {
        res.status(400);
        res.json({
          error: true,
          code: 'REQUIRE_BODY'
        });
        return;
      }

      const {
        email
      } = req.body;

      User.findOne({$or: [{email}, {username: email}]}, async (err, user) => {
        if (err) {
          res.status(500);
          res.json({
            error: true,
            code: '500'
          });
          return;
        }

        if (!user) {
          res.status(400);
          res.json({
            error: true,
            code: 'VALIDATION_ERRORS',
            validationErrors: [
              'USER_NOT_FOUND'
            ]
          });
          return;
        }

        if (user.verified) {
          res.status(400);
          res.json({
            error: true,
            code: 'VALIDATION_ERRORS',
            validationErrors: [
              'USER_ALREADY_VERIFIED'
            ]
          });
          return;
        }

        try {
          const verification_token = await helpers.randomString(30);
          user.verification_token = verification_token;
          await user.save();
          await mail.sendEmailVerification(user.email, verification_token);
          res.json({
            error: false
          });
        } catch (err) {
          res.status(500);
          res.json({
            error: true,
            code: '500'
          });
        }
      });
    });
  }
};
