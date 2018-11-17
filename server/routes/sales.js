import express from 'express';
import {
  ensureToken, isAttendant, isAdmin, verifyOrderInput,
} from '../helpers/validators';
import sendResponse from '../helpers/responses';
import {
  createOrder, getOrders,
} from '../crud/db-query';

const salesRouter = express.Router();


salesRouter.post('/', ensureToken, verifyOrderInput, (req, res) => {
  // sendResponse(res, 403, null, 'Input passed');
  if (!isAttendant(req.body.decoded.level)) {
    sendResponse(res, 403, null, 'You are not authorized to create order');
    return;
  }
  // const timeCheckedOut = (new Date()).getTime();
  createOrder(req.body.decoded.userId,
    req.body.products).then((result) => {
      let orderDetails = '';
    if(result[2] != null){
      orderDetails = result[2].rows;
    }
    res.send({
      message: 'Successfully created order',
      status: 200,
      orderDetails,
    });
  }).catch((e) => {
    console.log(e);
    sendResponse(res, 500, null, 'Internal server error');
  });
});

salesRouter.get('/', ensureToken, (req, res) => {
  if (!isAdmin(req.body.decoded.level)) {
    res.status(200).send({
      status: 200,
      message: 'successfully passed',
      orders: req.body.orderInput,
    });
    return;
  }
  getOrders().then((result) => {
    res.status(200).send({
      status: 200,
      message: 'successfully fetched orders',
      orders: result,
    });
  }).catch(() => {
    sendResponse(res, 500, null, 'Internal server error');
  });
});

salesRouter.get('/:id', ensureToken, (req, res) => {
  // query database
  getOrders(req.params.id).then((result) => {
    if (result.length <= 0) {
      sendResponse(res, 404, null, 'order not found');
      return;
    }
    if (isAdmin(req.body.decoded.level)
        || (isAttendant(req.body.decoded.level)
          && result[0].user_id === req.body.decoded.userId)) {
      res.status(200).send({
        status: 200,
        message: 'successfully fetched order',
        orderDetails: result,
      });
      return;
    }
    sendResponse(res, 403, null, 'You are not authorized to view this order');
  }).catch(() => {
    // console.log(e);
    sendResponse(res, 500, null, 'Internal server error');
  });
});


export default salesRouter;
