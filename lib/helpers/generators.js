const jose = require('jose');
const { createHash, randomBytes } = require('node:crypto');

const random = (bytes = 32) => jose.base64url.encode(randomBytes(bytes));

module.exports = {
  random,
  state: random,
  nonce: random,
  codeVerifier: random,
  codeChallenge: (codeVerifier) =>
    jose.base64url.encode(createHash('sha256').update(codeVerifier).digest()),
};
