import expect from 'expect';
import request from 'supertest';
import app from '../app';
import { getUser, clearTable } from '../crud/db-query';

const usersTable = 'users';

describe('POST /signup', () => {
  before((done) => {
    clearTable(usersTable)
      .then(() => {
        done();
      })
      .catch(e => done(e));
  });
  it('should create a new attendant for an admin', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: 'Mr Attendant Brown',
      email: 'mrsmith@gmail.com',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('account created');
      // ensure attendant is in database
      getUser('mrsmith@gmail.com')
        .then((result) => {
          expect(result[0].user_email).toBe('mrsmith@gmail.com');
        });
    }));

  it('should create a new attendant with invalid name', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: '',
      email: 'mrstee@gmail.com',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(400)
    .then((response) => {
      expect(response.body.error).toContain('Invalid input');
    }));

  it('should create a new attendant with invalid email', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: 'Mrs Valid name',
      email: 'Mrs Invalid Email',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(400)
    .then((response) => {
      expect(response.body.error).toContain('Invalid input');
    }));

  it('should not create a new attendant for an email in use', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: 'Mr New Attendant Brown',
      email: 'mrsmith@gmail.com',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(409)
    .then((response) => {
      expect(response.body.error).toContain('email in use');
      // ensure only one of that email exists in database
      getUser('mrsmith@gmail.com')
        .then((result) => {
          expect(result.length).toBe(1);
        });
    }));

  it('should not create a new attendant for an invalid admin token', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: 'Mr Attendant Bale',
      email: 'mrbale@gmail.com',
      token: 'byJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));
});
