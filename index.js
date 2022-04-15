const base58 = require('bs58')
const { Strategy } = require('passport')

module.exports = class PasswordlessStrategy extends Strategy {
  constructor(options, verify) {
    super()
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
        if (!this.options.store) {
          throw new Error(
            'Store parameter is missing! Please specify a passwordless datastore parameters!'
          )
        } else {
          this.options.store.initialized = true
        }
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
      }
    }

    //check for a valid delivery (a function or a described object for predefined ones)
    if (!this.options.delivery) {
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
      allowTokenReuse: Boolean(this.options.allowTokenReuse),
    })

    const that = this
    //initialize the delivery
    this.passwordless.addDelivery(that.options.delivery, {
      ttl: this.options.tokenLifeTime,
      tokenAlgorithm: that.options.maxTokenLength
        ? function () {
            var buf = crypto.randomBytes(that.options.maxTokenLength)
            return base58.encode(buf)
          }
        : that.options.tokenAlgorithm,
    })
  }

  //Passport authentication function
  authenticate = function (req, options) {
    //merge configiration options with the applied options and check if all was set right
    const tmpOptions = { ...this.options, ...options }

    //initialize passwordless with the current options
    if (tmpOptions.dynamicConfig) {
      this.initPasswordless()
    }

    //get request parameters to check the authentication state
    const combined = { ...req.query, ...req.body }
    var email = combined[tmpOptions.userField || 'user']
    var token = combined[tmpOptions.tokenField || 'token']
    var uid = combined[tmpOptions.uidField || 'uid']
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
          tmpOptions.delivery.type +
          ') or specify a valid token and uid!'
      )
    }
  }

  //Use the specified delivery to genrate and send a token.
  useDelivery = function (req) {
    const that = this
    //request a passwordlesstoken
    this.passwordless.requestToken(
      function (user, delivery, callback, req) {
        // usually you would want something like:
        that.options.access(user, function (err, user) {
          if (user) {
            callback(err, user)
          } else {
            callback('This user is not allowed to request a token!', null)
          }
        })
      },
      { ...that.options, userField: 'email' }
    )(req, {}, function (err) {
      if (err) {
        that.error(err)
      } else {
        that.success()
      }
    })
  }

  //Use the a sended token to checkup validity.
  verifyToken = function (req, token, uid) {
    const that = this
    //test the specified token and uid
    this.passwordless._tokenStore.authenticate(
      token,
      uid,
      function (err, valid) {
        if (err) {
          that.error(err)
        } else if (valid) {
          //if the token and uid combination was valid, verify the user
          that._verify(req, uid, function (err, user, info) {
            if (err) {
              return that.error(err)
            }
            if (!user) {
              return that.fail(info)
            }

            //if no token reuse is allowed, invalidate the token after the first authentication
            if (!that.options.allowTokenReuse) {
              that.passwordless._tokenStore.invalidateUser(
                uid.toString(),
                function () {
                  that.success(user, info)
                }
              )
            } else {
              that.success(user, info)
            }
          })
        } else {
          that.error('Invalid token and user id combination!')
        }
      }
    )
  }
}
