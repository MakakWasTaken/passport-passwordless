var util = require('util')
import * as crypto from 'crypto'
const base58 = require('bs58')
import { Strategy } from 'passport'

export default class PasswordlessStrategy extends Strategy {
  constructor(_options, _verify) {
    this.name = 'passwordless'

    //bind passwordless to the current instance to provide multiple strategies at the same time
    this.options = options
    this._verify = verify

    //check if dynamicConfig should not be used
    //  initialize only single passwordless instance with one configuration
    if (!this.options.dynamicConfig) {
      this.initPasswordless()
    }

    Strategy.call(this)
  }

  //checkup required parameters
  checkOptions = function () {
    //ensure that a store was given (existing store or path to store lib)
    if (!this.options.store) {
      throw new Error(
        'Store parameter is missing! Please specify a valid passwordless datastore! (https://passwordless.net/plugins)'
      )
    }

    //check if the store was set or if an allready existing passwordless store was applied
    if (!this.options.store.initialized) {
      if (!this.options.store.config) {
        throw new Error(
          'Store parameter is missing! Please specify a passwordless datastore parameters!'
        )
      }

      //check if the store variable is a string and try to load the required dataStore
      if (typeof this.options.store.path === 'string') {
        try {
          this.options.store.lib = require(this.options.store.path)
        } catch (ex) {
          throw new Error(
            'Passwordless datastore not found! Please specify a valid passwordless datastore! Path: ' +
              this.options.store.path
          )
        }

        //initialize new data store
        this.options.store = new this.options.store.lib(
          this.options.store.config
        )
        this.options.store.initialized = true
      } else {
        throw new Error(
          'Please specify a valid dataStore path to load the store!'
        )
      }
    }

    //check for a valid delivery (a function or a described object for predefined ones)
    if (!this.options.delivery || !util.isFunction(this.options.delivery)) {
      throw new Error(
        'Delivery parameter is missing or invalid! Please specify a valid delivery! ' +
          'The delivery must be a functions'
      )
    }

    if (!this.options.access) {
      this.options.access = function (user, callback) {
        callback(null, user)
      }
    }
  }

  //Initialize passwordless
  initPasswordless = function () {
    this.checkOptions(this.options)

    this.passwordless = new (require('passwordless').Passwordless)()

    //initialize the token store
    this.passwordless.init(this.options.store, {
      allowTokenReuse: !!this.options.allowTokenReuse,
    })

    //initialize the delivery
    this.passwordless.addDelivery(this.options.delivery, {
      ttl: this.options.tokenLifeTime,
      tokenAlgorithm: this.options.maxTokenLength
        ? function () {
            var buf = crypto.randomBytes(this.options.maxTokenLength)
            return base58.encode(buf)
          }
        : this.options.tokenAlgorithm,
    })
  }

  //Passport authentication function
  authenticate = function (req, options) {
    //merge configiration options with the applied options and check if all was set right
    this.options = { ...this.options, ...options }

    //initialize passwordless with the current options
    if (this.options.dynamicConfig) {
      this.initPasswordless()
    }

    //get request parameters to check the authentication state
    const combined = { ...req.query, ...req.body }
    var email = combined[this.options.userField || 'user']
    var token = combined[this.options.tokenField || 'token']
    var uid = combined[this.options.uidField || 'uid']
    //if a token and a uid was specified, verify the token
    //if only a user was specified, generate a token and send it
    //else send an error to specifiy valid values
    if (token && uid) {
      this.verifyToken(req, token, uid)
    } else if (email) {
      this.useDelivery(req)
    } else {
      this.error(
        'Could not authenticate! Please specify a user id for the specified delivery (' +
          this.options.delivery.type +
          ') or specify a valid token and uid!'
      )
    }
  }

  //Use the specified delivery to genrate and send a token.
  useDelivery = function (req) {
    //request a passwordlesstoken
    this.passwordless.requestToken(
      function (user, delivery, callback, req) {
        // usually you would want something like:
        this.options.access(user, function (err, user) {
          if (user) {
            callback(err, user)
          } else {
            callback('This user is not allowed to request a token!', null)
          }
        })
      },
      { ...this.options, userField: 'email' }
    )(req, {}, function (err) {
      if (err) {
        this.error(err)
      } else {
        this.pass()
      }
    })
  }

  //Use the a sended token to checkup validity.
  verifyToken = function (req, token, uid) {
    //test the specified token and uid
    this.passwordless._tokenStore.authenticate(
      token,
      uid,
      function (err, valid) {
        if (err) {
          this.error(err)
        } else if (valid) {
          //if the token and uid combination was valid, verify the user
          this._verify(req, uid, function (err, user, info) {
            if (err) {
              return this.error(err)
            }
            if (!user) {
              return this.fail(info)
            }

            //if no token reuse is allowed, invalidate the token after the first authentication
            if (!this.options.allowTokenReuse) {
              this.passwordless._tokenStore.invalidateUser(
                uid.toString(),
                function () {
                  this.success(user, info)
                }
              )
            } else {
              this.success(user, info)
            }
          })
        } else {
          this.error('Invalid token and user id combination!')
        }
      }
    )
  }
}
