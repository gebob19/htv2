const rateLimiter = require('express-rate-limit');
const isEmail = require('validator/lib/isEmail');
const fs = require('fs');
const path = require('path');
const Handlebars = require('handlebars');
const User = require('../models/user');
const mail = require('../mail');
const helpers = require('../helpers');

const resetPasswordPageTemplate = Handlebars.compile(String(fs.readFileSync(
  path.join(__dirname, '../templates/page-reset-password.handlebars'))));

const rateLimitResetPassword = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit up to 3 per IP
  message: { // Error json sent
    message: 'Too many requests. Please try again later.'
  }
});
  
module.exports = {
  attachRoute(app, recaptcha) {
    app.post('/reset-password', rateLimitResetPassword, recaptcha.middleware.verify, (req, res) => {
      if (req.recaptcha.error) {
        res.status(400);
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
          console.error(err);
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
            code: 'VALIDATION_ERROR',
            validationErrors: [
              'USER_NOT_FOUND'
            ]
          });
          return;
        }

        const token = await helpers.randomString(30);
        user.password_token = token;
        await user.save();
        await mail.sendPasswordReset(user.email, token);
        res.json({
          error: false
        });
      });
    });

    app.get('/reset-password/:token', (req, res) => {
      User.findOne({
        password_token: req.params.token
      }, (err, result) => {
        if (err) {
          res.status(500);
        } else if (!result) {
          res.status(400);
          res.send('INVALID_TOKEN');
        } else {
          res.set('Content-Type', 'text/html');
          res.send(resetPasswordPageTemplate({
            passwordToken: req.params.token
          }));
        }
      });
    });

    app.post('/reset-password/:token', (req, res) => {
      if (!req.body) {
        res.status(400);
        res.json({
          error: true,
          code: 'REQUIRE_BODY'
        });
        return;
      }

      const token = req.params.token;
      const password = req.body['new-password'];
      User.findOne({
        password_token: token
      }, async (err, user) => {
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
          res.send({
            error: true,
            code: 'INVALID_TOKEN'
          });
          return;
        }

        user.password_token = null;
        user.password = password;
        await user.save();
        res.redirect('/');
      });
    });
  }
};

