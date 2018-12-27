import expect from 'expect';
import request from 'supertest';
import app from '../app';
import { getUser } from '../crud/db-query';


describe('POST /signup', () => {
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

  it('should not create a new attendant with invalid name', () => request(app)
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

  it('should not create a new attendant with invalid email', () => request(app)
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

  it('should create a second attendant for an admin', () => request(app)
    .post('/api/v1/auth/signup')
    .send({
      name: 'Mr Attendant Gold',
      email: 'mrgold@gmail.com',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('account created');
      // ensure attendant is in database
      getUser('mrgold@gmail.com')
        .then((result) => {
          expect(result[0].user_email).toBe('mrgold@gmail.com');
        });
    }));
});

describe('POST /login', () => {
  it('should authenticate the store admin with valid password', () => request(app)
    .post('/api/v1/auth/login')
    .send({
      email: 'jpiper@admin.com',
      password: 'adminpassword',
    })
    .set('Accept', 'application/json')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully logged');
      expect(response.body.token).toBeTruthy();
    }));

  it('should not authenticate admin with invalid password', () => request(app)
    .post('/api/v1/auth/login')
    .send({
      email: 'jpiper@admin.com',
      password: 'wrongPassword',
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.userId).toBeFalsy();
      expect(response.body.error).toContain('Invalid');
    }));

  it('should authenticate the store attendant with default password', () => request(app)
    .post('/api/v1/auth/login')
    .send({
      email: 'mrsmith@gmail.com',
      password: 'attendantpassword',
    })
    .set('Accept', 'application/json')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully logged');
      expect(response.body.token).toBeTruthy();
    }));

  it('should authenticate a second store attendant with default password', () => request(app)
    .post('/api/v1/auth/login')
    .send({
      email: 'mrgold@gmail.com',
      password: 'attendantpassword',
    })
    .set('Accept', 'application/json')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully logged');
      expect(response.body.token).toBeTruthy();
    }));

  it('should not authenticate store attendant with invalid password', () => request(app)
    .post('/api/v1/auth/login')
    .send({
      email: 'mrsmith@gmail.com',
      password: 'wrongattendantpassword',
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.userId).toBeFalsy();
      expect(response.body.error).toContain('Invalid');
    }));
});
