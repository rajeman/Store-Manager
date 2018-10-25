import express from 'express';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { sendServerError, validateUser, ensureToken } from '../helpers/validators';
import { createUser, getUser } from '../crud/db-query';

dotenv.config();
const authRouter = express.Router();

let saltRound = process.env.SALT_ROUND;
let defaultPassword = process.env.DEFAULT_PASSWORD;
const attendantLevel = 1;

if (process.env.current_env === 'test') {
  saltRound = 6;
  defaultPassword = 'password';
}
authRouter.post('/signup', validateUser, ensureToken, (req, res) => {
  if (req.body.decoded.level !== 2) {
    // User not an admin. Has no access to route.
    res.status(403).send({
      error: 'You are not allowed to modify this content',
      status: 403,
    });
    return;
  }
  getUser(req.body.email)
    .then((result) => {
      if (result.length > 0) {
        res.status(409).send({
          error: 'email in use',
          status: 409,
        });
      } else {
        bcrypt.hash(defaultPassword, parseInt(saltRound, 10))
          .then((hash) => {
            // start storage process
            createUser({
              email: req.body.email,
              password: hash,
              name: req.body.name,
              level: attendantLevel,
            })
              .then((value) => {
                if (value === 1) {
                  res.status(201).send({
                    status: '201',
                    message: 'account created',
                  });
                } else {
                  sendServerError(res);
                }
              }).catch((e) => {
                console.log(e);
                sendServerError(res);
              });
          }).catch((e) => {
            console.log(e);
            sendServerError(res);
          });
      }
    })
    .catch((e) => {
      // hash the user's password for storage
      console.log(e);
      sendServerError(res);
    });
});

export default authRouter;
