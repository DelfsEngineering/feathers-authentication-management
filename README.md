## Forked to allow the `/user` service params passing

## feathers-authentication-management

[![Greenkeeper badge](https://badges.greenkeeper.io/feathersjs/feathers-authentication-management.svg)](https://greenkeeper.io/)

[![Build Status](https://travis-ci.org/feathersjs/feathers-authentication-management.png?branch=master)](https://travis-ci.org/feathersjs/feathers-authentication-management)
[![Code Climate](https://codeclimate.com/github/feathersjs/feathers-authentication-management/badges/gpa.svg)](https://codeclimate.com/github/feathersjs/feathers-authentication-management)
[![Test Coverage](https://codeclimate.com/github/feathersjs/feathers-authentication-management/badges/coverage.svg)](https://codeclimate.com/github/feathersjs/feathers-authentication-management/coverage)
[![Dependency Status](https://img.shields.io/david/feathersjs/feathers-authentication-management.svg?style=flat-square)](https://david-dm.org/feathersjs/feathers-authentication-management)
[![Download Status](https://img.shields.io/npm/dm/feathers-authentication-management.svg?style=flat-square)](https://www.npmjs.com/package/feathers-authentication-management)

> Adds sign up verification, forgotten password reset, and other capabilities to local
[`feathers-authentication`](https://docs.feathersjs.com/api/authentication/local-management.html).

This repo work with either the v1.0 rewrite of `feathers-authentication` or with v0.7.

## Multiple communication channels:

Traditionally users have been authenticated using their `username` or `email`.
However that landscape is changing.

Teens are more involved with cellphone SMS, whatsapp, facebook, QQ and wechat then they are with email.
Seniors may not know how to create an email account or check email, but they have smart phones
and perhaps whatsapp or wechat accounts.

A more flexible design would maintain multiple communication channels for a user
-- username, email address, phone number, handles for whatsapp, facebook, QQ, wechat --
which each uniquely identify the user.
The user could then sign in using any of their unique identifiers.
The user could also indicate how they prefer to be contacted.
Some may prefer to get password resets via long tokens sent by email;
others may prefer short numeric tokens sent by SMS or wechat.

`feathers-authentication` and `feathers-authentication-management`
provide much of the infrastructure necessary to implement such a scenario. 


## Documentation

Refer to [Documentation](https://docs.feathersjs.com/api/authentication/local-management.html).

Read a [step-by-step guide](https://medium.com/@codingfriend/how-to-setup-email-verification-in-feathersjs-72ce9882e744) created by Jon Paul Miles

## Tests

Run `npm test`


## License

MIT. See LICENSE.
