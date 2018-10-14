import expect from 'expect';
import request from 'supertest';
import app from '../app';
import products from '../models/products';

describe('POST /products', () => {
  it('should add a new product with valid parameters', () => request(app)
    .post('/api/v1/products')
    .send({
      name: '3D Printer',
      minInvent: 18,
      quantity: 500,
      level: 2,
    })
    .set('Accept', 'application/json')
    .expect(200)
    .then((response) => {
      expect(response.body.message).toContain('3D Printer');
      expect(products.productsList.length).toBe(3);
      expect(products.lastId).toBe(3);
    }));

it('should not add a new product with invalid parameters', () => request(app)
    .post('/api/v1/products')
    .send({
      name: 'Wireless Printer',
      minInvent: 0,
      quantity: 200,
      level: 2,
    })
    .set('Accept', 'application/json')
    .expect(400)
    .then((response) => {
      expect(response.body.error).toContain('Product name must be at least 3 characters');
      expect(products.productsList.length).toBe(3);
      expect(products.lastId).toBe(3);
    }));
it('should not allow non-admin to ad product', () => request(app)
    .post('/api/v1/products')
     .send({
      name: '3D Printer',
      minInvent: 18,
      quantity: 500,
      level: 1,
    })
    .set('Accept', 'application/json')
    .expect(403)
    .then((response) => {
      expect(response.body.error).toContain('not allowed to modify');
      expect(products.productsList.length).toBe(3);
      expect(products.lastId).toBe(3);
    }));
});