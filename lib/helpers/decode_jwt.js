const jose = require('jose');

module.exports = (token) => {
  if (typeof token !== 'string' || !token) {
    throw new TypeError('JWT must be a string');
  }

  const { length } = token.split('.');

  if (length === 5) {
    throw new TypeError('encrypted JWTs cannot be decoded');
  }

  if (length !== 3) {
    throw new Error('JWTs must have three components');
  }

  try {
    return {
      header: jose.decodeProtectedHeader(token),
      payload: jose.decodeJwt(token),
    };
  } catch (cause) {
    throw new Error('JWT is malformed', { cause });
  }
};
