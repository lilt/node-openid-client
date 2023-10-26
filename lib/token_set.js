const jose = require('jose');

const now = require('./helpers/unix_timestamp');

class TokenSet {
  constructor(values) {
    Object.assign(this, values);
    const { constructor, ...properties } = Object.getOwnPropertyDescriptors(
      this.constructor.prototype,
    );

    Object.defineProperties(this, properties);
  }

  set expires_in(value) {
    this.expires_at = now() + Number(value);
  }

  get expires_in() {
    return Math.max.apply(null, [this.expires_at - now(), 0]);
  }

  expired() {
    return this.expires_in === 0;
  }

  claims() {
    if (!this.id_token) {
      throw new TypeError('id_token not present in TokenSet');
    }

    return jose.decodeJwt(this.id_token);
  }
}

module.exports = TokenSet;
