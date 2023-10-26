const util = require('node:util');
const crypto = require('node:crypto');

module.exports = util.types.isKeyObject || ((obj) => obj && obj instanceof crypto.KeyObject);
