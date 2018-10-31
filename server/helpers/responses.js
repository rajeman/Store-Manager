
const sendResponse = (res, code, message, error) => {
  res.status(code).send({
    message: message || undefined,
    error: error || undefined,
    code,
  });
};

export default sendResponse;
