'use strict';

/* eslint-env node */

var errors = require('@feathersjs/errors');
var debug = require('debug')('authManagement:verifySignup');

var _require = require('./helpers'),
    getUserData = _require.getUserData,
    ensureObjPropsValid = _require.ensureObjPropsValid,
    ensureValuesAreStrings = _require.ensureValuesAreStrings,
    notifier = _require.notifier;

module.exports.verifySignupWithLongToken = function (options, verifyToken, params) {
  return Promise.resolve().then(function () {
    ensureValuesAreStrings(verifyToken);

    return verifySignup(options, { verifyToken: verifyToken }, { verifyToken: verifyToken }, params);
  });
};

module.exports.verifySignupWithShortToken = function (options, verifyShortToken, identifyUser, params) {
  return Promise.resolve().then(function () {
    ensureValuesAreStrings(verifyShortToken);
    ensureObjPropsValid(identifyUser, options.identifyUserProps);

    return verifySignup(options, identifyUser, { verifyShortToken: verifyShortToken }, params);
  });
};

function verifySignup(options, query, tokens, params) {
  debug('verifySignup', query, tokens);
  var users = options.app.service(options.service);
  var usersIdName = users.id;
  var sanitizeUserForClient = options.sanitizeUserForClient;

  params.query = query;
  return users.find(params).then(function (data) {
    return getUserData(data, ['isNotVerifiedOrHasVerifyChanges', 'verifyNotExpired']);
  }).then(function (user) {
    if (!Object.keys(tokens).every(function (key) {
      return tokens[key] === user[key];
    })) {
      return eraseVerifyProps(user, user.isVerified).then(function () {
        throw new errors.BadRequest('Invalid token. Get for a new one. (authManagement)', { errors: { $className: 'badParam' } });
      });
    }

    return eraseVerifyProps(user, user.verifyExpires > Date.now(), user.verifyChanges || {}).then(function (user1) {
      return notifier(options.notifier, 'verifySignup', user1, params);
    }).then(function (user1) {
      return sanitizeUserForClient(user1);
    });
  });

  function eraseVerifyProps(user, isVerified, verifyChanges) {
    var patchToUser = Object.assign({}, verifyChanges || {}, {
      isVerified: isVerified,
      verifyToken: null,
      verifyShortToken: null,
      verifyExpires: null,
      verifyChanges: {}
    });

    return patchUser(user, patchToUser);
  }

  function patchUser(user, patchToUser) {
    return users.patch(user[usersIdName], patchToUser, params) // needs users from closure
    .then(function () {
      return Object.assign(user, patchToUser);
    });
  }
}