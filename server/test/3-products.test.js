import expect from 'expect';
import request from 'supertest';
import app from '../app';


describe('POST /products', () => {
  it('should add a new product for an admin', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Authentic 3D Projector',
      price: 437,
      minimumInventory: 7,
      productQuantity: 250,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('Authentic 3D Projector');
    }));

  it('should second add a new product for an admin', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Bluetooth printer',
      price: 90,
      minimumInventory: 6,
      productQuantity: 420,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('Bluetooth printer');
    }));

  it('should add a third product for an admin', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Wireless Mouse',
      price: 6,
      minimumInventory: 100,
      productQuantity: 300,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('Wireless Mouse');
    }));

  it('should add a fourth product for an admin', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Executive Car Charger',
      price: 8,
      minimumInventory: 3,
      productQuantity: 1020,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw',
    })
    .set('Accept', 'application/json')
    .expect(201)
    .then((response) => {
      expect(response.body.message).toContain('Executive Car Charger');
    }));

  it('should not add a new product with an invalid token', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Wireless Mouse',
      price: 7,
      minimumInventory: 65,
      productQuantity: 250,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJmZ2RmZ2RyZyIsImVtYWlsIjoiemlAZ21haWwuY29tIiwidXNlcklkIjoyLCJsZXZlbCI6MSwiaWF0IjoxNTQwNDU4NDA3fQ.tnEcnTPnPRT-h4bk69RmA90hi436j3c2oSuJMb1vx5M',
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));

  it('should not add a new product for an attendant', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Wireless Mouse',
      price: 7,
      minimumInventory: 65,
      productQuantity: 250,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJNciBBdHRlbmRhbnQgQnJvd24iLCJlbWFpbCI6Im1yc21pdGhAZ21haWwuY29tIiwidXNlcklkIjo5NywibGV2ZWwiOjEsImlhdCI6MTU0MDUxMDQ4Mn0.33jlhGMWr103MtOEgYkvX3xK33cr4Gn4FY9ZlOeO5JE',
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('not authorized');
    }));

  it('should return 422 error with invalid request body', () => request(app)
    .post('/api/v1/products')
    .send({
      productName: 'Wireless Keyboard',
      price: 4.37,
      minimumInventory: 7,
      productQuantity: 250,
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTgzNjR9.oXXINp8rYzHHzdlAfRpwGjE4Xvw7zF_TE2gdXDpROBQ',
    })
    .set('Accept', 'application/json')
    .expect(422)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));
});

describe('GET /products', () => {
  it('should fetch all products for authenticated user', () => request(app)
    .get('/api/v1/products/')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully fetched');
      expect(response.body.products[0].product_name).toContain('Authentic 3D Projector');
      expect(response.body.products).toHaveLength(4);
    }));

  it('should not fetch products for non-authenticated user', () => request(app)
    .get('/api/v1/products/')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));
});

describe('GET /products:id', () => {
  it('should fetch the product for authenticated user', () => request(app)
    .get('/api/v1/products/1')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully fetched');
      expect(response.body.product[0].product_id).toBe(1);
      expect(response.body.product[0].product_price).toBe(437);
    }));

  it('should not fetch product for non-authenticated user', () => request(app)
    .get('/api/v1/products/15')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));

  it('should not fetch invalid product', () => request(app)
    .get('/api/v1/products/10')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(404)
    .then((response) => {
      expect(response.body.error).toContain('not found');
    }));
});

describe('PUT /products:id', () => {
  it('should modify the product for an authenticated admin', () => request(app)
    .put('/api/v1/products/1')
    .send({
      productName: 'Smart Torchlight',
      price: 300,
      minimumInventory: 14,
      productQuantity: 250,
    })
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully updated');
    }));

  it('should not modify the product for an attendant', () => request(app)
    .put('/api/v1/products/1')
    .send({
      productName: 'Wireless Keyboard',
      price: 301,
      minimumInventory: 12,
      productQuantity: 250,
    })
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJNciBBdHRlbmRhbnQgQnJvd24iLCJlbWFpbCI6Im1yc21pdGhAZ21haWwuY29tIiwidXNlcklkIjo5NywibGV2ZWwiOjEsImlhdCI6MTU0MDUxMDQ4Mn0.33jlhGMWr103MtOEgYkvX3xK33cr4Gn4FY9ZlOeO5JE')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('not authorized');
    }));

  it('should not modify the product for non-authenticated user', () => request(app)
    .put('/api/v1/products/1')
    .send({
      productName: 'Wireless Keyboard',
      price: 301,
      minimumInventory: 12,
      productQuantity: 250,
    })
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));

  it('should not modify invalid product', () => request(app)
    .put('/api/v1/products/8')
    .send({
      productName: 'Mouse Pad',
      price: 101,
      minimumInventory: 10,
      productQuantity: 250,
    })
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(404)
    .then((response) => {
      expect(response.body.error).toContain('Invalid product');
    }));
});


describe('DELETE /products:id', () => {
  it('should delete the product for authenticated user', () => request(app)
    .delete('/api/v1/products/1')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('successfully deleted');
    }));

  it('should not delete product for non-authenticated user', () => request(app)
    .delete('/api/v1/products/2')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('Invalid');
    }));

  it('should not delete invalid product', () => request(app)
    .delete('/api/v1/products/9')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOjMwMywidXNlcm5hbWUiOiJKZWZmZXJzb24gUGlwZXIiLCJlbWFpbCI6ImpwaXBlckBhZG1pbi5jb20iLCJ1c2VySWQiOjEsImxldmVsIjoyLCJpYXQiOjE1NDA0NTMyMDJ9.HplqH5tLSIr5_l69D2FuUs3mpyBqtZjFSEouLSuIFGw')
    .expect(404)
    .then((response) => {
      expect(response.body.error).toContain('not found');
    }));
});
