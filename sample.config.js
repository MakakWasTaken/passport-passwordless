//example using redis datastore
module.exports = {
  //If this property will be set to true, each authentication request generates a new passwordless instance to handle multiple and dynamic configurations
  //If it's set to false, the passwordless instance will be created by instantiating the strategy
  dynamicConfig: false,

  //all passwordless internal parameters, that are used to parse the request query object
  userField: 'user',
  tokenField: 'tokenField',
  uidField: 'uidField',
  deliveryField: 'delivery',
  originField: null,

  //token relevant parameters
  allowTokenReuse: true,
  tokenLifeTime: 1000 * 60 * 10,

  //specify maximal token length
  maxTokenLength: 16,

  //If you want to create your own token type use this function, to use your own algorithm.
  //tokenAlgorithm : function() {
  //  Function shall return the token in sync mode (default: Base58 token)
  //},

  //includes the store configuration
  //setup a path to the node_module that should be used
  //setup a configuration array that will be applied to the store constructor
  //internally it looks like the following code :
  //  var store = require(this.options.store);
  //  store.call(this.options.store.config);
  store: {
    path: __dirname + '/node_modules/passwordless-redis',
    config: [6379, '127.0.0.1', {}],
  },

  //specify the delivery configurations
  //following object contains an example with emailjs
  //
  //Notice : currently only a delivery for emailjs is written
  //  If you want to use another delivery, feel free to implement it or apply a function like the following as the delivery
  //  function(options) {
  //    var email = require(options.path);
  //    var smtp  = email.server.connect(options.config.server);
  //
  //  return function(tokenToSend, uidToSend, recipient, callback, req) {
  //    ... do delivery stuff..
  //    callback(err);
  //  });
  delivery: function (tokenToSend, uidToSend, recipient, callback, req) {
    //Send the token using the
  },

  //is used to check if an user is authorized to request a token
  //call the callback with an error and an user object (user object needs an parameter called "id" to specify it's email adress, sms, ...)
  //the default access functions contains the following function
  access: function (user, callback) {
    callback(null, user)
  },
}
