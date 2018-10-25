import validator from 'validator';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { productsMap } from '../models/products';

dotenv.config();
let secretKey = process.env.TOKEN_KEY;

if (process.env.current_env === 'test') {
  secretKey = 'my_secret_key';
}

const isPositiveInteger = s => /^\+?[1-9][\d]*$/.test(s);


const verifyOrderInput = (req, res, next) => {
  const orderInput = req.body;
  let shouldExit = false;
  const orderItem = { productsArray: [] };
  if (orderInput && orderInput.attendantId && isPositiveInteger(orderInput.attendantId)) {
    orderItem.attendantId = orderInput.attendantId;
    const { productsArray } = orderInput;
    if (productsArray instanceof Array && productsArray.length > 0) {
      const duplicateProductsId = new Map();
      productsArray.every((inputProduct) => {
        if (duplicateProductsId.get(String(inputProduct.productId))) {
          res.status(400).send({
            error: `product with id ${inputProduct.productId} is ordered twice`,
            status: 400,
          });
          shouldExit = true;
          return false;
        }
        duplicateProductsId.set(String(inputProduct.productId), 'dummy');

        const product = productsMap.get(String(inputProduct.productId));
        if (product) {
          const inputProductQuantity = inputProduct.quantity;
          if (isPositiveInteger(inputProductQuantity)) {
            const storeQuantity = product.quantity;
            if (storeQuantity >= inputProductQuantity) {
              orderItem.productsArray.push({
                productId: inputProduct.productId,
                quantity: inputProductQuantity,
                pricePerProduct: product.price,
              });
              return true;
            }
            res.status(400).send({
              error: `order quantity (${inputProductQuantity}) of ${product.name} with id: ${product.id} is more than available quantity (${storeQuantity})`,
              status: 400,
            });
            shouldExit = true;
            return false;
          }
          shouldExit = true;
          res.status(400).send({
            error: 'Product quantity should be a positive integer',
            status: 400,
          });
          return false;
        }
        shouldExit = true;
        res.status(400).send({
          error: `Product with id ${inputProduct.productId} does not exist`,
          status: 400,
        });
        return false;
      });
    } else {
      shouldExit = true;
      res.status(400).send({
        error: 'Array containing products should be provided',
        status: 400,
      });
    }
  } else {
    shouldExit = true;
    res.status(403).send({
      error: 'Only attendants can create sales orders. Please specify a valid attendant id',
      status: 403,
    });
    return false;
  }
  if (!shouldExit) {
    req.orderItem = orderItem;
    return next();
  }
  return false;
};

const sendServerError = (res) => {
  res.send({
    error: 'Internal server error',
    status: 500,
  });
};

const sendAuthenticationError = (res) => {
  res.status(422).send({
    error: 'Invalid username or password',
    status: 422,
  });
};

const validateUser = (req, res, next) => {
  const { name, email } = req.body;
  const validName = typeof name === 'string' && name.trim() !== '' && name.trim().length >= 3;
  const validEmail = typeof email === 'string' && validator.isEmail(email);
  if (validEmail && validName) {
    next();
  } else {
    res.status(400).send({
      error: 'Invalid input. Make sure email is valid and name'
      + ' must be at least 3 characters ',
    });
  }
};

const ensureToken = (req, res, next) => {
  let bearerToken = req.body.token;
  if (!bearerToken) {
    bearerToken = '';
  }
  try {
    const decoded = jwt.verify(bearerToken, secretKey);
    req.body.decoded = decoded;
    next();
  } catch (err) {
    res.status(403).send({
      error: 'Invalid Token',
      status: 403,
    });
  }
};

export {
  verifyOrderInput, sendServerError, sendAuthenticationError, validateUser, ensureToken,
};
