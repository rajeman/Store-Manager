import express from 'express';
import { products, productsMap } from '../models/products';

const isPositiveInteger = s => /^\+?[1-9][\d]*$/.test(s);
const admin = 2;
const productsRouter = express.Router();

const verifyParameters = (req, res, next) => {
  const parameter = req.body;
  if (parameter && parameter.level !== admin) {
    res.status(403).send({
      error: 'You are not allowed to modify this content',
      status: 403,
    });
    return;
  }
  if (parameter && parameter.name && parameter.name.trim().length > 2 && isPositiveInteger(parameter.minInvent)
    && isPositiveInteger(parameter.quantity) && isPositiveInteger(parameter.price)) {
    next();
  } else {
    res.status(400).send({
      error: 'Product name must be at least 3 characters with the minimum inventory, price and quantity greater than zero',
      status: 400,
    });
  }
};


productsRouter.post('/', verifyParameters, (req, res) => {
  const reqBody = req.body;
  const newProduct = {
    id: products.lastId + 1,
    quantity: reqBody.quantity,
    minInvent: reqBody.minInvent,
    price: reqBody.price,
    name: reqBody.name,
    created: new Date(),
  };
  products.productsList.push(newProduct);
  products.lastId += 1;
  productsMap.set(String(newProduct.id), newProduct);
  res.send({
    message: `'${newProduct.name}' successfully added`,
  });
});

productsRouter.get('/', (req, res) => {
  res.send(products.productsList.filter(product => product.quantity > 0));
});

productsRouter.get('/:id', (req, res) => {
  const product = productsMap.get(String(req.params.id));
  if (product) {
    res.send({
      message: 'product found',
      product,
    });
  } else {
    res.status(404).send({
      error: 'cannot find product',
    });
  }
});


export default productsRouter;
