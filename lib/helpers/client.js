const crypto = require('node:crypto');
const { strict: assert } = require('node:assert');

const jose = require('jose');

const { RPError } = require('../errors');
const TokenSet = require('../token_set');

const isPlainObject = require('./is_plain_object');
const { CLOCK_TOLERANCE } = require('./consts');
const decodeJWT = require('./decode_jwt');
const { assertIssuerConfiguration } = require('./assert');
const { random } = require('./generators');
const now = require('./unix_timestamp');
const request = require('./request');
const { keystores } = require('./weak_cache');
const merge = require('./merge');
const { queryKeyStore } = require('./issuer');

const formUrlEncode = (value) => encodeURIComponent(value).replace(/%20/g, '+');

function secretForAlg(alg) {
  if (!this.client_secret) {
    throw new TypeError('client_secret is required');
  }

  if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
    return encryptionSecret.call(this, parseInt(RegExp.$1, 10));
  }

  if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
    return encryptionSecret.call(this, parseInt(RegExp.$2 || RegExp.$1, 10));
  }

  return new TextEncoder().encode(this.client_secret);
}

function encryptionSecret(len) {
  const hash = len <= 256 ? 'sha256' : len <= 384 ? 'sha384' : len <= 512 ? 'sha512' : false;
  if (!hash) {
    throw new Error('unsupported symmetric encryption key derivation');
  }

  return crypto
    .createHash(hash)
    .update(this.client_secret)
    .digest()
    .slice(0, len / 8);
}

async function clientAssertion(endpoint, payload) {
  let alg = this[`${endpoint}_endpoint_auth_signing_alg`];
  if (!alg) {
    assertIssuerConfiguration(
      this.issuer,
      `${endpoint}_endpoint_auth_signing_alg_values_supported`,
    );
  }

  if (this[`${endpoint}_endpoint_auth_method`] === 'client_secret_jwt') {
    if (!alg) {
      const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
      alg =
        Array.isArray(supported) && supported.find((signAlg) => /^HS(?:256|384|512)/.test(signAlg));
    }

    if (!alg) {
      throw new RPError(
        `failed to determine a JWS Algorithm to use for ${
          this[`${endpoint}_endpoint_auth_method`]
        } Client Assertion`,
      );
    }

    return new jose.CompactSign(Buffer.from(JSON.stringify(payload)))
      .setProtectedHeader({ alg })
      .sign(secretForAlg.call(this, alg));
  }

  const keystore = await keystores.get(this);

  if (!keystore) {
    throw new TypeError('no client jwks provided for signing a client assertion with');
  }

  if (!alg) {
    const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
    alg =
      Array.isArray(supported) &&
      supported.find((signAlg) => keystore.get({ alg: signAlg, use: 'sig' }));
  }

  if (!alg) {
    throw new RPError(
      `failed to determine a JWS Algorithm to use for ${
        this[`${endpoint}_endpoint_auth_method`]
      } Client Assertion`,
    );
  }

  const key = keystore.get({ alg, use: 'sig' });
  if (!key) {
    throw new RPError(
      `no key found in client jwks to sign a client assertion with using alg ${alg}`,
    );
  }

  return new jose.CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ alg, kid: key.jwk && key.jwk.kid })
    .sign(await key.keyObject(alg));
}

async function decryptIdToken(token) {
  if (!this.id_token_encrypted_response_alg) {
    return token;
  }

  let idToken = token;

  if (idToken instanceof TokenSet) {
    if (!idToken.id_token) {
      throw new TypeError('id_token not present in TokenSet');
    }
    idToken = idToken.id_token;
  }

  const expectedAlg = this.id_token_encrypted_response_alg;
  const expectedEnc = this.id_token_encrypted_response_enc;

  const result = await decryptJWE.call(this, idToken, expectedAlg, expectedEnc);

  if (token instanceof TokenSet) {
    token.id_token = result;
    return token;
  }

  return result;
}

async function decryptJWE(jwe, expectedAlg, expectedEnc = 'A128CBC-HS256') {
  const header = jose.decodeProtectedHeader(jwe);

  if (header.alg !== expectedAlg) {
    throw new RPError({
      printf: ['unexpected JWE alg received, expected %s, got: %s', expectedAlg, header.alg],
      jwt: jwe,
    });
  }

  if (header.enc !== expectedEnc) {
    throw new RPError({
      printf: ['unexpected JWE enc received, expected %s, got: %s', expectedEnc, header.enc],
      jwt: jwe,
    });
  }

  const getPlaintext = (result) => new TextDecoder().decode(result.plaintext);
  let plaintext;
  if (expectedAlg.match(/^(?:RSA|ECDH)/)) {
    const keystore = await keystores.get(this);

    const protectedHeader = jose.decodeProtectedHeader(jwe);

    for (const key of keystore.all({
      ...protectedHeader,
      use: 'enc',
    })) {
      plaintext = await jose
        .compactDecrypt(jwe, await key.keyObject(protectedHeader.alg), {
          keyManagementAlgorithms: [expectedAlg],
          contentEncryptionAlgorithms: [expectedEnc],
        })
        .then(getPlaintext, () => {});
      if (plaintext) break;
    }
  } else {
    plaintext = await jose
      .compactDecrypt(
        jwe,
        secretForAlg.call(this, expectedAlg === 'dir' ? expectedEnc : expectedAlg),
        {
          keyManagementAlgorithms: [expectedAlg],
          contentEncryptionAlgorithms: [expectedEnc],
        },
      )
      .then(getPlaintext, () => {});
  }

  if (!plaintext) {
    throw new RPError({
      message: 'failed to decrypt JWE',
      jwt: jwe,
    });
  }
  return plaintext;
}

async function authFor(endpoint, { clientAssertionPayload } = {}) {
  const authMethod = this[`${endpoint}_endpoint_auth_method`];
  switch (authMethod) {
    case 'self_signed_tls_client_auth':
    case 'tls_client_auth':
    case 'none':
      return { form: { client_id: this.client_id } };
    case 'client_secret_post':
      if (typeof this.client_secret !== 'string') {
        throw new TypeError(
          'client_secret_post client authentication method requires a client_secret',
        );
      }
      return { form: { client_id: this.client_id, client_secret: this.client_secret } };
    case 'private_key_jwt':
    case 'client_secret_jwt': {
      const timestamp = now();
      const audience = [
        ...new Set([this.issuer.issuer, this.issuer.token_endpoint].filter(Boolean)),
      ];

      const assertion = await clientAssertion.call(this, endpoint, {
        iat: timestamp,
        exp: timestamp + 60,
        jti: random(),
        iss: this.client_id,
        sub: this.client_id,
        aud: audience,
        ...clientAssertionPayload,
      });

      return {
        form: {
          client_id: this.client_id,
          client_assertion: assertion,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        },
      };
    }
    case 'client_secret_basic': {
      // This is correct behaviour, see https://tools.ietf.org/html/rfc6749#section-2.3.1 and the
      // related appendix. (also https://github.com/panva/node-openid-client/pull/91)
      // > The client identifier is encoded using the
      // > "application/x-www-form-urlencoded" encoding algorithm per
      // > Appendix B, and the encoded value is used as the username; the client
      // > password is encoded using the same algorithm and used as the
      // > password.
      if (typeof this.client_secret !== 'string') {
        throw new TypeError(
          'client_secret_basic client authentication method requires a client_secret',
        );
      }
      const encoded = `${formUrlEncode(this.client_id)}:${formUrlEncode(this.client_secret)}`;
      const value = Buffer.from(encoded).toString('base64');
      return { headers: { Authorization: `Basic ${value}` } };
    }
    default: {
      throw new TypeError(`missing, or unsupported, ${endpoint}_endpoint_auth_method`);
    }
  }
}

function resolveResponseType() {
  const { length, 0: value } = this.response_types;

  if (length === 1) {
    return value;
  }

  return undefined;
}

function resolveRedirectUri() {
  const { length, 0: value } = this.redirect_uris || [];

  if (length === 1) {
    return value;
  }

  return undefined;
}

async function authenticatedPost(
  endpoint,
  opts,
  { clientAssertionPayload, endpointAuthMethod = endpoint, DPoP } = {},
) {
  const auth = await authFor.call(this, endpointAuthMethod, { clientAssertionPayload });
  const requestOpts = merge(opts, auth);

  const mTLS =
    this[`${endpointAuthMethod}_endpoint_auth_method`].includes('tls_client_auth') ||
    (endpoint === 'token' && this.tls_client_certificate_bound_access_tokens);

  let targetUrl;
  if (mTLS && this.issuer.mtls_endpoint_aliases) {
    targetUrl = this.issuer.mtls_endpoint_aliases[`${endpoint}_endpoint`];
  }

  targetUrl = targetUrl || this.issuer[`${endpoint}_endpoint`];

  if ('form' in requestOpts) {
    for (const [key, value] of Object.entries(requestOpts.form)) {
      if (typeof value === 'undefined') {
        delete requestOpts.form[key];
      }
    }
  }

  return request.call(
    this,
    {
      ...requestOpts,
      method: 'POST',
      url: targetUrl,
      headers: {
        ...(endpoint !== 'revocation'
          ? {
              Accept: 'application/json',
            }
          : undefined),
        ...requestOpts.headers,
      },
    },
    { mTLS, DPoP },
  );
}

function verifyPresence(payload, jwt, prop) {
  if (payload[prop] === undefined) {
    throw new RPError({
      message: `missing required JWT property ${prop}`,
      jwt,
    });
  }
}

async function validateJWT(
  jwt,
  expectedAlg,
  required = ['iss', 'sub', 'aud', 'exp', 'iat'],
  { aadIssValidation, additionalAuthorizedParties } = {},
) {
  const isSelfIssued = this.issuer.issuer === 'https://self-issued.me';
  const timestamp = now();
  let header;
  let payload;
  try {
    ({ header, payload } = decodeJWT(jwt));
  } catch (err) {
    throw new RPError({
      printf: ['failed to decode JWT (%s: %s)', err.name, err.message],
      jwt,
    });
  }

  if (header.alg !== expectedAlg) {
    throw new RPError({
      printf: ['unexpected JWT alg received, expected %s, got: %s', expectedAlg, header.alg],
      jwt,
    });
  }

  if (isSelfIssued) {
    required = [...required, 'sub_jwk'];
  }

  required.forEach(verifyPresence.bind(undefined, payload, jwt));

  if (payload.iss !== undefined) {
    let expectedIss = this.issuer.issuer;

    if (aadIssValidation) {
      expectedIss = this.issuer.issuer.replace('{tenantid}', payload.tid);
    }

    if (payload.iss !== expectedIss) {
      throw new RPError({
        printf: ['iss mismatch, expected %s, got: %s', expectedIss, payload.iss],
        jwt,
      });
    }
  }

  if (payload.iat !== undefined) {
    if (typeof payload.iat !== 'number') {
      throw new RPError({
        message: 'JWT iat claim must be a JSON numeric value',
        jwt,
      });
    }
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number') {
      throw new RPError({
        message: 'JWT nbf claim must be a JSON numeric value',
        jwt,
      });
    }
    if (payload.nbf > timestamp + this[CLOCK_TOLERANCE]) {
      throw new RPError({
        printf: [
          'JWT not active yet, now %i, nbf %i',
          timestamp + this[CLOCK_TOLERANCE],
          payload.nbf,
        ],
        now: timestamp,
        tolerance: this[CLOCK_TOLERANCE],
        nbf: payload.nbf,
        jwt,
      });
    }
  }

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number') {
      throw new RPError({
        message: 'JWT exp claim must be a JSON numeric value',
        jwt,
      });
    }
    if (timestamp - this[CLOCK_TOLERANCE] >= payload.exp) {
      throw new RPError({
        printf: ['JWT expired, now %i, exp %i', timestamp - this[CLOCK_TOLERANCE], payload.exp],
        now: timestamp,
        tolerance: this[CLOCK_TOLERANCE],
        exp: payload.exp,
        jwt,
      });
    }
  }

  if (payload.aud !== undefined) {
    if (Array.isArray(payload.aud)) {
      if (payload.aud.length > 1 && !payload.azp) {
        throw new RPError({
          message: 'missing required JWT property azp',
          jwt,
        });
      }

      if (!payload.aud.includes(this.client_id)) {
        throw new RPError({
          printf: [
            'aud is missing the client_id, expected %s to be included in %j',
            this.client_id,
            payload.aud,
          ],
          jwt,
        });
      }
    } else if (payload.aud !== this.client_id) {
      throw new RPError({
        printf: ['aud mismatch, expected %s, got: %s', this.client_id, payload.aud],
        jwt,
      });
    }
  }

  if (payload.azp !== undefined) {
    if (typeof additionalAuthorizedParties === 'string') {
      additionalAuthorizedParties = [this.client_id, additionalAuthorizedParties];
    } else if (Array.isArray(additionalAuthorizedParties)) {
      additionalAuthorizedParties = [this.client_id, ...additionalAuthorizedParties];
    } else {
      additionalAuthorizedParties = [this.client_id];
    }

    if (!additionalAuthorizedParties.includes(payload.azp)) {
      throw new RPError({
        printf: ['azp mismatch, got: %s', payload.azp],
        jwt,
      });
    }
  }

  let keys;

  if (isSelfIssued) {
    try {
      assert(isPlainObject(payload.sub_jwk));
      const key = await jose.importJWK(payload.sub_jwk, header.alg);
      assert.equal(key.type, 'public');
      keys = [
        {
          keyObject() {
            return key;
          },
        },
      ];
    } catch (err) {
      throw new RPError({
        message: 'failed to use sub_jwk claim as an asymmetric JSON Web Key',
        jwt,
      });
    }
    if ((await jose.calculateJwkThumbprint(payload.sub_jwk)) !== payload.sub) {
      throw new RPError({
        message: 'failed to match the subject with sub_jwk',
        jwt,
      });
    }
  } else if (header.alg.startsWith('HS')) {
    keys = [secretForAlg.call(this, header.alg)];
  } else if (header.alg !== 'none') {
    keys = await queryKeyStore.call(this.issuer, { ...header, use: 'sig' });
  }

  if (!keys && header.alg === 'none') {
    return { protected: header, payload };
  }

  for (const key of keys) {
    const verified = await jose
      .compactVerify(jwt, key instanceof Uint8Array ? key : await key.keyObject(header.alg), {
        algorithms: [expectedAlg],
      })
      .catch(() => {});
    if (verified) {
      return {
        payload,
        protected: verified.protectedHeader,
        key,
      };
    }
  }

  throw new RPError({
    message: 'failed to validate JWT signature',
    jwt,
  });
}

module.exports = {
  resolveResponseType,
  resolveRedirectUri,
  authFor,
  authenticatedPost,
  encryptionSecret,
  secretForAlg,
  decryptJWE,
  decryptIdToken,
  validateJWT,
};
