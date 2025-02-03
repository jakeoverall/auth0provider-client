const { initialize, hasPermissions, authGuard, authSettled, decodeToken, AUTH_EVENTS, Identity, requiresPermissions, onAuthLoaded,  } = require('./Auth0Provider.js')

module.exports = {
  AUTH_EVENTS: AUTH_EVENTS,
  initialize: initialize,
  hasPermissions: hasPermissions,
  authGuard: authGuard,
  authSettled: authSettled,
  decodeToken: decodeToken,
  Identity: Identity,
  requiresPermissions,
  onAuthLoaded
}
