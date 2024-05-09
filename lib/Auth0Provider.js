const auth0 = require('@auth0/auth0-spa-js')
const EventEmitter = require('./EventEmitter.js')

/**
 @type {AuthPlugin}
 */
let instance = null

class AuthPlugin extends EventEmitter {
  /**
   * 
   * @param {auth0.Auth0ClientOptions} options 
   */
  constructor(options) {
    super()
    if (instance) { return instance }
    if (!options) { throw new Error('Invalid Auth0 Configuration') }
    this.loading = true
    this.AUTH_EVENTS = {
      LOADING: 'LOADING',
      LOADED: 'LOADED',
      AUTHENTICATED: 'AUTHENTICATED',
      TOKEN_CHANGE: 'TOKEN_CHANGE'
    }
    this.user = {}
    this.userInfo = {}
    this.identity = {}
    this.isAuthenticated = false
    this.bearer = ''
    this.popupOpen = false
    /** @type {auth0.Auth0Client} */
    this.auth0Client = null
    this.error = null
    this.options = options
    instance = this
  }

  /** Authenticates the user using a popup window
   * @param {auth0.PopupLoginOptions} [o]
  */
  async loginWithPopup(o) {
    instance.popupOpen = true
    try {
      await instance.auth0Client.loginWithPopup(o)
      instance.user = await instance.auth0Client.getUser()
      instance.user = instance.user || {}
      await instance.getUserData()
      instance.isAuthenticated = true
    } catch (error) {
      if (error instanceof auth0.PopupTimeoutError) {
        error.popup.close();
      }
    } finally {
      instance.popupOpen = false
    }
  }

  /** Handles the callback when logging in using a redirect */
  async handleRedirectCallback() {
    instance.loading = true
    try {
      await instance.auth0Client.handleRedirectCallback()
      instance.user = await instance.auth0Client.getUser()
      await instance.getUserData()
      instance.isAuthenticated = true
    } catch (e) {
      instance.error = e
    } finally {
      instance.loading = false
    }
  }

  /** Authenticates the user using the redirect method
   * @param {auth0.RedirectLoginOptions} [o]
  */
  loginWithRedirect(o) {
    o = o || {
      authorizationParams: { redirect_uri: window.location.href }
    }

    return instance.auth0Client.loginWithRedirect(o)
  }

  /**
 * Returns the access token. If the token is invalid or missing, a new one is retrieved
 * @param {auth0.GetTokenSilentlyOptions} [o]
 */
  async getTokenSilently(o) {
    const token = await instance.auth0Client.getTokenSilently(o)
    instance.getIdentityClaims(token)
    instance.emit(instance.AUTH_EVENTS.TOKEN_CHANGE, this)
    return token
  }

  /**
 * @param {string[] | string} permissions
 */
  hasPermissions(permissions) {
    if (!Array.isArray(permissions)) {
      permissions = [permissions]
    }
    if (!instance.identity.permissions) {
      return false
    }
    while (permissions.length) {
      const next = permissions.pop()
      const /**
         * @param {any} p
         */
        found = instance.identity.permissions.find(p => p === next)
      if (!found) {
        return false
      }
    }
    return true
  }

  /**
 * @param {string[] | string} roles
 */
  hasRoles(roles) {
    if (!Array.isArray(roles)) {
      roles = [roles]
    }
    if (!instance.userInfo.roles) {
      return false
    }
    while (roles.length) {
      const next = roles.pop()
      const /**
         * @param {any} r
         */
        found = instance.userInfo.roles.find(r => r === next)
      if (!found) {
        return false
      }
    }
    return true
  }

  /**
 * @param {string} token
 */
  async getIdentityClaims(token) {
    const decoded = decodeToken(token)
    instance.identity = JSON.parse(decoded)
    return instance.identity
  }

  /**
 * Gets the access token using a popup window
 * @param {auth0.GetTokenWithPopupOptions} [o]
 */
  async getTokenWithPopup(o) {
    const token = await instance.auth0Client.getTokenWithPopup(o)
    instance.getIdentityClaims(token)
    instance.emit(instance.AUTH_EVENTS.TOKEN_CHANGE, this)
    return token
  }

  async getUserData() {
    try {
      if (instance.userInfo) { return instance.emit(instance.AUTH_EVENTS.AUTHENTICATED, this) }
      const token = await instance.getTokenSilently()
      await instance.getIdentityClaims(token)
      instance.bearer = 'Bearer ' + token
      // eslint-disable-next-line no-undef
      const res = await fetch(`https://${instance.options.domain}/userinfo`, {
        headers: {
          authorization: instance.bearer
        }
      })

      const userData = await res.json()
      for (const key in userData) {
        let keep = key
        if (key.includes('https')) {
          keep = keep.slice(keep.lastIndexOf('/') + 1)
        }
        instance.userInfo[keep] = userData[key]
      }
      instance.user = instance.user || {}
      instance.user.isAuthenticated = true
      instance.emit(instance.AUTH_EVENTS.AUTHENTICATED, this)
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(e)
    }
  }

  /** Logs the user out and removes their session on the authorization server
   * @param {auth0.LogoutOptions} [o]
  */
  logout(o) {
    o = o || { logoutParams: { returnTo: window.location.origin } }
    const logout = instance.auth0Client.logout(o)
    instance.bearer = ''
    instance.user = {}
    instance.userInfo = {}
    instance.identity = {}
    instance.isAuthenticated = false
    return logout
  }

  verifyAuth0() {
    if (instance.auth0Client) { return instance }
    instance.createAuthInstance(instance.options)
  }

  /**
 * Use this lifecycle method to instantiate the SDK client
 * @param {auth0.Auth0ClientOptions} options
 */
  async createAuthInstance(options) {
    instance.emit(instance.AUTH_EVENTS.LOADING)
    // Create a new instance of the SDK client using members of the given options object
    instance.auth0Client = await auth0.createAuth0Client(options)

    try {
      // If the user is returning to the app after authentication..
      if (
        window.location.search.includes('code=') &&
        window.location.search.includes('state=')
      ) {
        // handle the redirect and retrieve tokens
        await instance.auth0Client.handleRedirectCallback()
        window.history.replaceState({}, document.title, "/");
      }
    } catch (e) {
      instance.error = e
    } finally {
      // Initialize our internal authentication state
      instance.isAuthenticated = await instance.auth0Client.isAuthenticated()

      if (instance.isAuthenticated) {
        instance.user = await instance.auth0Client.getUser()
        await instance.getUserData()
      }

      instance.loading = false
      instance.emit(instance.AUTH_EVENTS.LOADED)
    }
  }
}

function onAuthLoaded(cb) {
  return new Promise((resolve) => {
    const authService = instance
    if (!authService.loading) {
      if (typeof cb === 'function') { cb(authService) }
      return resolve(authService)
    }
    authService.on(authService.AUTH_EVENTS.LOADED, () => {
      resolve(authService)
      if (typeof cb === 'function') { cb(authService) }
    })
  })
}
async function getUserAsync() {
  await onAuthLoaded()
  return instance.user
}

function b64DecodeUnicode(str = '.') {
  try {
    return decodeURIComponent(
      // eslint-disable-next-line no-undef
      atob(str).replace(/(.)/g, function (m, p) {
        let code = p
          .charCodeAt(0)
          .toString(16)
          .toUpperCase()
        if (code.length < 2) {
          code = '0' + code
        }
        return '%' + code
      })
    )
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[AUTH0-PROVIDER-ERROR] unable to decode token', e)
  }
}
function decodeToken(str = '.') {
  try {
    const payload = str.split('.')[1]
    let output = payload.replace(/-/g, '+').replace(/_/g, '/')
    switch (output.length % 4) {
      case 0:
        break
      case 2:
        output += '=='
        break
      case 3:
        output += '='
        break
      default:
        throw new Error('Illegal base64url string!')
    }

    return b64DecodeUnicode(output)
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[AUTH0-PROVIDER-ERROR] unable to decode token', e)
  }
}

/**
 * @param {auth0.Auth0ClientOptions} options
 */
function initialize(options) {
  const plugin = new AuthPlugin(options)
  plugin.verifyAuth0()
  return plugin
}

/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
async function authGuard(to, from, next) {
  try {
    await onAuthLoaded()
    if (instance.isAuthenticated) {
      return next()
    }
    return instance.loginWithRedirect({ appState: { targetUrl: to.fullPath } })
  } catch (e) {
    return instance.loginWithRedirect({ appState: { targetUrl: to.fullPath } })
  }
}

/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
async function authSettled(to, from, next) {
  try {
    await onAuthLoaded()
    next()
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[AUTH_SETTLED]', e)
    return next()
  }
}

/**
 * @param {string | string[]} permissions
 */
const hasPermissions = (permissions) => instance.hasPermissions(permissions)

module.exports = {
  AuthPlugin,
  decodeToken,
  hasPermissions,
  authGuard,
  authSettled,
  initialize,
  getUserAsync
}
