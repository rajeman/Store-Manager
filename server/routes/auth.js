import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import sendResponse from '../helpers/responses';
import constants from '../helpers/constants';

import {
  validateUser, ensureToken, isAdmin,
} from '../helpers/validators';
import { createUser, getUser } from '../crud/db-query';

const authRouter = express.Router();

let saltRound = process.env.SALT_ROUND;
let secretKey = process.env.TOKEN_KEY;
let defaultPassword = process.env.DEFAULT_PASSWORD;

if (process.env.current_env === 'test') {
  secretKey = process.env.TEST_TOKEN_KEY;
  saltRound = process.env.TEST_SALT_ROUND;
  defaultPassword = process.env.TEST_DEFAULT_PASSWORD;
}
authRouter.post('/signup', validateUser, ensureToken, (req, res) => {
  // User not an admin. Has no access to route.
  if (!isAdmin) {
    sendResponse(res, 403, null, 'You are not allowed to modify this content');
    return;
  }
  getUser(req.body.email)
    .then((result) => {
      if (result.length > 0) {
        sendResponse(res, 409, null, 'email in use');
      } else {
        bcrypt.hash(defaultPassword, parseInt(saltRound, 10))
          .then((hash) => {
            // start storage process
            createUser({
              email: req.body.email,
              password: hash,
              name: req.body.name,
              level: constants.attendantLevel,
            })
              .then((value) => {
                if (value === 1) {
                  sendResponse(res, 201, `account created for '${req.body.name}'`);
                } else {
                  sendResponse(res, 500, null, 'Internal server error');
                }
              }).catch(() => {
                // console.log(e);
                sendResponse(res, 500, null, 'Internal server error');
              });
          }).catch(() => {
            // console.log(e);
            sendResponse(res, 500, null, 'Internal server error');
          });
      }
    })
    .catch(() => {
      // console.log(e);
      sendResponse(res, 500, null, 'Internal server error');
    });
});

authRouter.post('/login', (req, res) => {
  // confirm email exists in database
  getUser(req.body.email)
    .then((result) => {
      if (!req.body.password) {
        req.body.password = '';
      }
      if (bcrypt.compareSync(req.body.password, result[0].user_password)) {
        const payload = {};
        payload.username = result[0].user_name;
        payload.email = result[0].user_email;
        payload.userId = result[0].user_id;
        payload.level = result[0].user_level;
        const token = jwt.sign(payload, secretKey);
        res.header('Authorization', `Bearer ${token}`);
        res.status(200).send({
          message: 'successfully logged in',
          level: result[0].user_level,
          token,
        });
      } else {
        sendResponse(res, 403, null, 'Invalid username or password');
      }
    })
    .catch(() => {
      // console.log(e);
      sendResponse(res, 403, null, 'Invalid username or password');
    });
});


export default authRouter;
