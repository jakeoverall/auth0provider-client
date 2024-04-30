const Auth0Provider = require('./Auth0Provider.js')

module.exports = {
  Auth0Provider,
  initialize: Auth0Provider.initialize,
  hasPermissions: Auth0Provider.hasPermissions,
  authGuard: Auth0Provider.authGuard,
  authSettled: Auth0Provider.authSettled,
  decodeToken: Auth0Provider.decodeToken
}
