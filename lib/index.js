const { initialize, hasPermissions, authGuard, authSettled, decodeToken } = require('./Auth0Provider.js')

module.exports = {
  initialize: initialize,
  hasPermissions: hasPermissions,
  authGuard: authGuard,
  authSettled: authSettled,
  decodeToken: decodeToken
}
