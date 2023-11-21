const url = require('url');
const { format } = require('util');

const cloneDeep = require('./helpers/deep_clone');
const { RPError, OPError } = require('./errors');
const { BaseClient } = require('./client');
const { random, codeChallenge } = require('./helpers/generators');
const pick = require('./helpers/pick');
const { resolveResponseType, resolveRedirectUri } = require('./helpers/client');
const debug = require("debug")("openid-client");

function verified(err, user, info = {}) {
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(info);
  } else {
    this.success(user, info);
  }
}

function OpenIDConnectStrategy(
  { client, params = {}, passReqToCallback = false, sessionKey, usePKCE = true, extras = {} } = {},
  verify,
) {
  debug(
    "!!!!!!!!!!!!!!! DEBUG statements will be logged for the Customized OpenIDConnectStrategy."
  );
  if (!(client instanceof BaseClient)) {
    throw new TypeError('client must be an instance of openid-client Client');
  }

  if (typeof verify !== 'function') {
    throw new TypeError('verify callback must be a function');
  }

  if (!client.issuer || !client.issuer.issuer) {
    throw new TypeError('client must have an issuer with an identifier');
  }

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._passReqToCallback = passReqToCallback;
  this._usePKCE = usePKCE;
  this._key = sessionKey || `oidc:${url.parse(this._issuer.issuer).hostname}`;
  this._params = cloneDeep(params);

  // state and nonce are handled in authenticate()
  delete this._params.state;
  delete this._params.nonce;

  this._extras = cloneDeep(extras);

  if (!this._params.response_type) this._params.response_type = resolveResponseType.call(client);
  if (!this._params.redirect_uri) this._params.redirect_uri = resolveRedirectUri.call(client);
  if (!this._params.scope) this._params.scope = 'openid';

  if (this._usePKCE === true) {
    const supportedMethods = Array.isArray(this._issuer.code_challenge_methods_supported)
      ? this._issuer.code_challenge_methods_supported
      : false;

    if (supportedMethods && supportedMethods.includes('S256')) {
      this._usePKCE = 'S256';
    } else if (supportedMethods && supportedMethods.includes('plain')) {
      this._usePKCE = 'plain';
    } else if (supportedMethods) {
      throw new TypeError(
        'neither code_challenge_method supported by the client is supported by the issuer',
      );
    } else {
      this._usePKCE = 'S256';
    }
  } else if (typeof this._usePKCE === 'string' && !['plain', 'S256'].includes(this._usePKCE)) {
    throw new TypeError(`${this._usePKCE} is not valid/implemented PKCE code_challenge_method`);
  }

  this.name = url.parse(client.issuer.issuer).hostname;
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  (async () => {
    const client = this._client;
    if (!req.session) {
      throw new TypeError('authentication requires session support');
    }
    const reqParams = client.callbackParams(req);
    const sessionKey = this._key;

    const { 0: parameter, length } = Object.keys(reqParams);

    /**
     * Start authentication request if this has no authorization response parameters or
     * this might a login initiated from a third party as per
     * https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin.
     */
    if (length === 0 || (length === 1 && parameter === 'iss')) {
    /* start authentication request */
    if (Object.keys(reqParams).length === 0) {
      debug(
        "OpenIDConnectStrategy.authenticate start-authentication-request block entered"
      );
      // provide options object with extra authentication parameters
      const params = {
        state: random(),
        ...this._params,
        ...options,
      };

      if (!params.nonce && params.response_type.includes('id_token')) {
        params.nonce = random();
      }

      req.session[sessionKey] = pick(params, 'nonce', 'state', 'max_age', 'response_type');

      if (this._usePKCE && params.response_type.includes('code')) {
        const verifier = random();
        req.session[sessionKey].code_verifier = verifier;

        switch (this._usePKCE) {
          case 'S256':
            params.code_challenge = codeChallenge(verifier);
            params.code_challenge_method = 'S256';
            break;
          case 'plain':
            params.code_challenge = verifier;
            break;
        }
      }

      debug(
        'OpenIDConnectStrategy.authenticate start-authentication-request is about to redirect to client.authorizationUrl using "params":',
        params
      );
      this.redirect(client.authorizationUrl(params));
      return;
    }
    /* end authentication request */

    /* start authentication response */

    debug(
      "OpenIDConnectStrategy.authenticate start-authentication-response is beginning"
    );
    const session = req.session[sessionKey];
    if (Object.keys(session || {}).length === 0) {
      debug(
        "OpenIDConnectStrategy.authenticate start-authentication-response found no expected authorization request details in session and is about to throw error"
      );
      throw new Error(
        format(
          'did not find expected authorization request details in session, req.session["%s"] is %j',
          sessionKey,
          session,
        ),
      );
    }

    const {
      state,
      nonce,
      max_age: maxAge,
      code_verifier: codeVerifier,
      response_type: responseType,
    } = session;

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    const opts = {
      redirect_uri: this._params.redirect_uri,
      ...options,
    };

    const checks = {
      state,
      nonce,
      max_age: maxAge,
      code_verifier: codeVerifier,
      response_type: responseType,
    };

    const tokenset = await client.callback(opts.redirect_uri, reqParams, checks, this._extras);

    debug(
      "OpenIDConnectStrategy.authenticate start-authentication-response is about to call client.callback to get tokenset, passing: ",
      {
        "opts.redirect_uri": opts.redirect_uri,
        reqParams,
        checks
      }
    );
    const passReq = this._passReqToCallback;
    const loadUserinfo = this._verify.length > (passReq ? 3 : 2) && client.issuer.userinfo_endpoint;

    const args = [tokenset, verified.bind(this)];

    if (loadUserinfo) {
      if (!tokenset.access_token) {
        debug(
          "OpenIDConnectStrategy.authenticate start-authentication-response did not find expected access token and is about to throw error, tokenset=",
          tokenset
        );
        throw new RPError({
          message:
            'expected access_token to be returned when asking for userinfo in verify callback',
          tokenset,
        });
      }
      debug(
        "OpenIDConnectStrategy.authenticate start-authentication-response about to await call to client.userInfo to get userinfo"
      );
      const userinfo = await client.userinfo(tokenset);
      debug(
        "OpenIDConnectStrategy.authenticate start-authentication-response client.userinfo returned with userinfo=",
        userinfo
      );
      args.splice(1, 0, userinfo);
    }

    if (passReq) {
      args.unshift(req);
    }

    debug(
      "OpenIDConnectStrategy.authenticate start-authentication-response about to call this._verify"
    );
    this._verify(...args);
    debug(
      "OpenIDConnectStrategy.authenticate start-authentication-response this._verify returned without error/failure"
    );
    /* end authentication response */
  }})().catch((error) => {
    if (
      (error instanceof OPError &&
        error.error !== 'server_error' &&
        !error.error.startsWith('invalid')) ||
      error instanceof RPError
    ) {
      debug(
        "OpenIDConnectStrategy.authenticate catch is about to call this.fail with errror=",
        error
      );
      this.fail(error);
    } else {
      debug(
        "OpenIDConnectStrategy.authenticate catch is about to call this.error with errror=",
        error
      );
      this.error(error);
    }
  });
};

module.exports = OpenIDConnectStrategy;
