const crypto = require('node:crypto');

const jose = require('jose');

const { random } = require('./generators');
const pick = require('./pick');
const isKeyObject = require('./is_key_object');
const isPlainObject = require('./is_plain_object');

async function getDPoPJwk(keyObject) {
  this.dpopJwkCache ||= new WeakMap();
  if (this.dpopJwkCache.has(keyObject)) {
    return this.dpopJwkCache.get(keyObject);
  }

  const jwk = pick(await jose.exportJWK(keyObject), 'kty', 'crv', 'x', 'y', 'e', 'n');

  this.dpopJwkCache.set(keyObject, jwk);

  return jwk;
}

async function dpopProof(payload, privateKey, accessToken) {
  if (!isPlainObject(payload)) {
    throw new TypeError('payload must be a plain object');
  }

  if (!isKeyObject(privateKey) && privateKey[Symbol.toStringTag] !== 'CryptoKey') {
    throw new TypeError('"DPoP" option must be a private KeyObject or CryptoKey');
  }

  if (privateKey.type !== 'private') {
    throw new TypeError('"DPoP" option must be a private key');
  }

  let alg = determineDPoPAlgorithm.call(this, privateKey);

  if (!alg) {
    throw new TypeError('could not determine DPoP JWS Algorithm');
  }

  return new jose.SignJWT({
    ath: accessToken
      ? jose.base64url.encode(crypto.createHash('sha256').update(accessToken).digest())
      : undefined,
    ...payload,
  })
    .setProtectedHeader({
      alg,
      typ: 'dpop+jwt',
      jwk: await getDPoPJwk.call(this, privateKey, privateKey),
    })
    .setIssuedAt()
    .setJti(random())
    .sign(privateKey);
}

function determineDPoPAlgorithmFromCryptoKey(cryptoKey) {
  switch (cryptoKey.algorithm.name) {
    case 'Ed25519':
    case 'Ed448':
      return 'EdDSA';
    case 'ECDSA': {
      switch (cryptoKey.algorithm.namedCurve) {
        case 'P-256':
          return 'ES256';
        case 'P-384':
          return 'ES384';
        case 'P-521':
          return 'ES512';
        default:
          break;
      }
      break;
    }
    case 'RSASSA-PKCS1-v1_5':
      return `RS${cryptoKey.algorithm.hash.name.slice(4)}`;
    case 'RSA-PSS':
      return `PS${cryptoKey.algorithm.hash.name.slice(4)}`;
    default:
      throw new TypeError('unsupported DPoP private key');
  }
}

let determineDPoPAlgorithm;
if (jose.cryptoRuntime === 'node:crypto') {
  const nodeKeyDetailsToJOSEAlg = ({ namedCurve }) => {
    switch (namedCurve) {
      case 'prime256v1':
        return 'ES256';
      case 'secp384r1':
        return 'ES384';
      case 'secp521r1':
        return 'ES512';
      case 'secp256k1':
        return 'ES256K';
      default:
        throw new TypeError('unsupported DPoP private key curve');
    }
  };

  determineDPoPAlgorithm = function (privateKey) {
    if (privateKey[Symbol.toStringTag] === 'CryptoKey') {
      return determineDPoPAlgorithmFromCryptoKey(privateKey);
    }

    switch (privateKey.asymmetricKeyType) {
      case 'ed25519':
      case 'ed448':
        return 'EdDSA';
      case 'ec':
        return nodeKeyDetailsToJOSEAlg(privateKey.asymmetricKeyDetails);
      case 'rsa':
      case 'rsa-pss':
        return determineRsaAlgorithm(privateKey, this.issuer.dpop_signing_alg_values_supported);
      default:
        throw new TypeError('unsupported DPoP private key');
    }
  };

  const RSPS = /^(?:RS|PS)(?:256|384|512)$/;
  function determineRsaAlgorithm(privateKey, valuesSupported) {
    if (Array.isArray(valuesSupported)) {
      let candidates = valuesSupported.filter(RegExp.prototype.test.bind(RSPS));
      if (privateKey.asymmetricKeyType === 'rsa-pss') {
        candidates = candidates.filter((value) => value.startsWith('PS'));
      }
      return ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS384'].find((preferred) =>
        candidates.includes(preferred),
      );
    }

    return 'PS256';
  }
} else {
  determineDPoPAlgorithm = determineDPoPAlgorithmFromCryptoKey;
}

module.exports = dpopProof;
