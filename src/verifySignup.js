/* eslint-env node */

const errors = require('@feathersjs/errors');
const debug = require('debug')('authManagement:verifySignup');

const {
  getUserData,
  ensureObjPropsValid,
  ensureValuesAreStrings,
  notifier
} = require('./helpers');

module.exports.verifySignupWithLongToken = function(options, verifyToken, params) {
  return Promise.resolve()
    .then(() => {
      ensureValuesAreStrings(verifyToken);

      return verifySignup(options, { verifyToken }, { verifyToken }, params);
    });
};

module.exports.verifySignupWithShortToken = function(options, verifyShortToken, identifyUser, params) {
  return Promise.resolve()
    .then(() => {
      ensureValuesAreStrings(verifyShortToken);
      ensureObjPropsValid(identifyUser, options.identifyUserProps);

      return verifySignup(options, identifyUser, { verifyShortToken }, params);
    });
};

function verifySignup(options, query, tokens, params) {
  debug('verifySignup', query, tokens);
  const users = options.app.service(options.service);
  const usersIdName = users.id;
  const {
    sanitizeUserForClient
  } = options;
  params.query = query
  return users.find(params)
    .then(data => getUserData(data, ['isNotVerifiedOrHasVerifyChanges', 'verifyNotExpired']))
    .then(user => {
      if (!Object.keys(tokens).every(key => tokens[key] === user[key])) {
        return eraseVerifyProps(user, user.isVerified)
          .then(() => {
            throw new errors.BadRequest('Invalid token. Get for a new one. (authManagement)', { errors: { $className: 'badParam' } });
          });
      }

      return eraseVerifyProps(user, user.verifyExpires > Date.now(), user.verifyChanges || {})
        .then(user1 => notifier(options.notifier, 'verifySignup', user1, params))
        .then(user1 => sanitizeUserForClient(user1));
    });

  function eraseVerifyProps(user, isVerified, verifyChanges) {
    const patchToUser = Object.assign({}, verifyChanges || {}, {
      isVerified,
      verifyToken: null,
      verifyShortToken: null,
      verifyExpires: null,
      verifyChanges: {}
    });

    return patchUser(user, patchToUser);
  }

  function patchUser(user, patchToUser) {
    return users.patch(user[usersIdName], patchToUser, params) // needs users from closure
      .then(() => Object.assign(user, patchToUser));
  }
}
