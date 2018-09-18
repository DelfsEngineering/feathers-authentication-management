/* eslint-env node */

const debug = require('debug')('authManagement:resendVerifySignup');

const {
  getUserData,
  ensureObjPropsValid,
  getLongToken,
  getShortToken,
  notifier
} = require('./helpers');

// {email}, {cellphone}, {verifyToken}, {verifyShortToken},
// {email, cellphone, verifyToken, verifyShortToken}
module.exports = function resendVerifySignup(options, identifyUser, notifierOptions) {
  debug('resendVerifySignup', identifyUser);
  const users = options.app.service(options.service);
  const usersIdName = users.id;
  const {
    sanitizeUserForClient
  } = options;

  return Promise.resolve()
    .then(() => {
      ensureObjPropsValid(identifyUser,
        options.identifyUserProps.concat('verifyToken', 'verifyShortToken')
      );

      var params = notifierOptions.params // new
      params.query = identifyUser
      return params;
    })
    .then(params =>
      Promise.all([
        users.find(params)
        .then(data => getUserData(data, ['isNotVerified'])),
        getLongToken(options.longTokenLen),
        getShortToken(options.shortTokenLen, options.shortTokenDigits)
      ])
    )
    .then(([user, longToken, shortToken]) =>
      patchUser(user, {
        isVerified: false,
        verifyExpires: Date.now() + options.delay,
        verifyToken: longToken,
        verifyShortToken: shortToken
      })
    )
    .then(user => notifier(options.notifier, 'resendVerifySignup', user, notifierOptions))
    .then(user => sanitizeUserForClient(user));

  function patchUser(user, patchToUser) {
    return users.patch(user[usersIdName], patchToUser, notifierOptions.params) // needs users from closure
      .then(() => Object.assign(user, patchToUser));
  }
};
