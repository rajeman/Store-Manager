import express from 'express';
import { verifyOrderInput } from '../helpers/validators';
import { orders, ordersMap } from '../models/orders';
import { productsMap } from '../models/products';
import {
  sendServerError, ensureToken
} from '../helpers/validators';
import {
  getUser, createProduct, getProducts, deleteProducts, updateProducts,
} from '../crud/db-query';

const salesRouter = express.Router();
const admin = 2;

salesRouter.post('/', verifyOrderInput, (req, res) => {
  const { orderItem } = req;
  orderItem.orderDate = new Date().getTime(); 

  let totalPrice = 0;
  orderItem.productsArray.forEach((product) => {
    totalPrice += product.pricePerProduct * product.quantity;
    const storeProduct = productsMap.get(String(product.productId));
    storeProduct.quantity -= product.quantity;
  });
  orderItem.totalPrice = totalPrice;

  res.send({
    message: 'Successfully created order',
    order: orderItem,
  });
});

/*salesRouter.post('/', verifyOrderInput, (req, res) => {
  const { orderItem } = req;
  orderItem.orderDate = new Date();
  orderItem.orderId = orders.lastOrderId + 1;
  orders.lastOrderId += 1;
  let totalPrice = 0;
  orderItem.productsArray.forEach((product) => {
    totalPrice += product.pricePerProduct * product.quantity;
    const storeProduct = productsMap.get(String(product.productId));
    storeProduct.quantity -= product.quantity;
  });
  orderItem.totalPrice = totalPrice;
  orders.ordersList.push(orderItem);
  ordersMap.set(String(orderItem.orderId), orderItem);

  res.send({
    message: 'Successfully created order',
    order: orderItem,
  });
});*/

salesRouter.get('/', (req, res) => {
  const { level } = req.query;

  if (level !== String(admin)) {
    res.status(403).send({
      error: 'You are not allowed to access this content',
      status: 403,
    });
    return;
  }
  res.send({
    message: 'Successfully fetched orders',
    orders: orders.ordersList,
  });
});

salesRouter.get('/:id', (req, res) => {
  const { level, attendantId } = req.query;
  const { id } = req.params;
  const orderDetails = ordersMap.get(String(id));

  if (level === String(admin)) {
    if (orderDetails) {
      res.send({
        message: 'Successfully fetched order',
        orderDetails,
      });
    } else {
      res.status(404).send({
        error: 'Invalid order id',
        status: 404,
      });
    }
    return;
  }

  if (attendantId) {
    if (!orderDetails) {
      res.status(403).send({
        error: 'You are not allowed to access this content',
        status: 403,
      });
      return;
    }
    if (orderDetails && String(orderDetails.attendantId) === attendantId) {
      res.send({
        message: 'Successfully fetched order',
        orderDetails,
      });
      return;
    }
  }
  res.status(403).send({
    error: 'You are not allowed to access this content',
    status: 403,
  });
});


export default salesRouter;
