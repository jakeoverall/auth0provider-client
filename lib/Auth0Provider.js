const auth0 = require('@auth0/auth0-spa-js')

const AUTH_EVENTS = {
  LOADING: 'LOADING',
  LOADED: 'LOADED',
  AUTHENTICATED: 'AUTHENTICATED',
  TOKEN_CHANGE: 'TOKEN_CHANGE'
}
/**
 * Identity is a class that represents the user's identity claims granted from auth0
 */
class Identity {
  constructor(data) {
    /**
     * Audience - Who or what the token is intended for
     * @type {string[]}
     */
    this.aud = data.aud
    /**
     * The Authorized Party - the party to which the ID Token was issued
     * @type {string}
     * */
    this.azp = data.azp
    /**
     * The user's email address
     * @type {string}
     * */
    this.email = data.email
    /**
     * Has the user's email been verified
     * @type {boolean}
     * */
    this.email_verified = data.email_verified
    /**
     * Expiration time of the token
     * @type {number}
     * */
    this.exp = data.exp
    /**
     * Issued At - the time at which the token was issued
     * @type {number}
     * */
    this.iat = data.iat
    /**
     * Issuer - the party that issued the token
     * @type {string}
     * */
    this.iss = data.iss
    /**
     * The user's name
     * @type {string}
     * */
    this.name = data.name
    /**
     * The user's set of permissions if included
     * @type {string[]}
     * */
    this.permissions = data.permissions || []
    /**
     * The user's picture url
     * @type {string}
     * */
    this.picture = data.picture
    /**
     * The scopes granted to the token 
     * @type {string}
     * */
    this.scope = data.scope
    /**
     * The user's subject identifier - a unique identifier for the user
     * @type {string}
     * */
    this.sub = data.sub
    /**
     * The last time the token was updated
     * @type {string}
     * */
    this.updated_at = data.updated_at
    for (const key in data) {
      this[key] = data[key]
    }
  }
}




/**
 @type {AuthPlugin}
 */
let instance = null

/**
 * @param {AuthPlugin|any} newInstance
 * Useful for testing
 * */
const setInstance = (newInstance) => {
  instance = newInstance;
};

class AuthPlugin {
  /**
   * 
   * @param {auth0.Auth0ClientOptions} options 
   */
  constructor(options) {
    if (instance) { return instance }
    if (!options) { throw new Error('Invalid Auth0 Configuration') }
    this._listeners = {}
    this._state = AUTH_EVENTS.LOADING
    this.state = AUTH_EVENTS.LOADING
    /**
     * @type {Identity}
     */
    this.identity = null
    this.bearer = ''
    this.popupOpen = false
    /** @type {auth0.Auth0Client} */
    this.auth0Client = null
    this.error = null
    this.options = options
    instance = this
    this.verifyAuth0()
  }

  /**
   * @param {string} val
   */
  set state(val) {
    this._state = val
    this.emit(val)
  }

  get state() {
    return this._state
  }


  /**
   * @param {string | number} event
   * @param {function} fn
   * @param {any} thisContext
   */
  on(event, fn, thisContext = null) {
    if (typeof fn !== 'function') { return }
    this._listeners[event] = this._listeners[event] || []
    // @ts-ignore
    fn.ctx = thisContext
    this._listeners[event].push(fn)
  }

  /**
   * @param {string | number} event
   * @param {function} fn
   */
  off(event, fn) {
    this._listeners[event] = this._listeners[event] || []
    const i = this._listeners[event].indexOf(fn)
    if (i === -1) { return }
    this._listeners[event].splice(i, 1)
  }

  /**
   * @param {string} event
   * @param {any} [payload]
   */
  emit(event, payload) {
    this._listeners[event] = this._listeners[event] || []
    const length = this._listeners[event].length
    for (let i = 0; i < length; i++) {
      const fn = this._listeners[event][i]
      fn.ctx
        ? fn.call(fn.ctx, payload)
        : fn(payload)
    }
  }

  /** Authenticates the user using a popup window
   * @param {auth0.PopupLoginOptions} [o]
  */
  async loginWithPopup(o) {
    try {
      await instance.auth0Client.loginWithPopup(o)
      await instance.getUserData()
      instance.state = AUTH_EVENTS.AUTHENTICATED
    } catch (error) {
      if (error instanceof auth0.PopupTimeoutError) {
        error.popup.close();
      }
    }
  }

  /** Handles the callback when logging in using a redirect */
  async handleRedirectCallback() {
    instance.state = AUTH_EVENTS.LOADING
    try {
      await instance.auth0Client.handleRedirectCallback()
      await instance.getUserData()
      const url = new URL(window.location.href);
      url.searchParams.delete('code');
      url.searchParams.delete('state');
      window.history.replaceState({}, document.title, url);
      instance.state = AUTH_EVENTS.AUTHENTICATED
    } catch (e) {
      instance.error = e
      instance.state = AUTH_EVENTS.LOADED
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
    instance.emit(AUTH_EVENTS.TOKEN_CHANGE, this)
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
  * @param {string} token
  */
  async getIdentityClaims(token) {
    const decoded = decodeToken(token)
    instance.identity = new Identity(JSON.parse(decoded))
    return instance.identity
  }

  /**
  * Gets the access token using a popup window
  * @param {auth0.GetTokenWithPopupOptions} [o]
  */
  async getTokenWithPopup(o) {
    const token = await instance.auth0Client.getTokenWithPopup(o)
    instance.getIdentityClaims(token)
    instance.emit(AUTH_EVENTS.TOKEN_CHANGE, this)
    return token
  }

  async getUserData() {
    try {
      if (instance.identity) {
        return instance.emit(AUTH_EVENTS.AUTHENTICATED, this)
      }
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
        instance.identity[keep] = userData[key]
      }
      instance.state = AUTH_EVENTS.AUTHENTICATED
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
    instance.state = AUTH_EVENTS.LOADING
    // Create a new instance of the SDK client using members of the given options object
    instance.auth0Client = await auth0.createAuth0Client(options)

    try {
      // If the user is returning to the app after authentication..
      if (
        window.location.search.includes('code=') &&
        window.location.search.includes('state=')
      ) {
        // handle the redirect and retrieve tokens
        await instance.handleRedirectCallback()
      }
    } catch (e) {
      instance.error = e
    } finally {
      // Initialize our internal authentication state
      const isAuthenticated = await instance.auth0Client.isAuthenticated()
      if (isAuthenticated) {
        await instance.getUserData()
      } else {
        instance.state = AUTH_EVENTS.LOADED
      }
    }
  }
}

function onAuthLoaded(cb) {
  return new Promise((resolve) => {
    if (instance.state != AUTH_EVENTS.LOADING) {
      if (typeof cb === 'function') { cb(instance) }
      return resolve(instance)
    }
    function next() {
      resolve(instance)
      if (typeof cb === 'function') { cb(instance) }
    }
    instance.on(AUTH_EVENTS.AUTHENTICATED, next)
    instance.on(AUTH_EVENTS.LOADED, next)
  })
}
async function getUserAsync() {
  await onAuthLoaded()
  return instance.identity
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
  return new AuthPlugin(options)
}

/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
async function authGuard(to, from, next) {
  try {
    await onAuthLoaded()
    if (instance.state == AUTH_EVENTS.AUTHENTICATED) {
      return next()
    }
    return instance.loginWithRedirect()
  } catch (e) {
    return instance.loginWithRedirect()
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
 * 
 * @param {String | String[]} permissions 
 * @returns 
 */
function requiresPermissions(permissions = []) {
  return async (to, from, next) => {
    try {
      await onAuthLoaded()
      if(instance.state != AUTH_EVENTS.AUTHENTICATED){
        return instance.loginWithRedirect()
      }
      const allowed = instance.hasPermissions(permissions)
      if (!allowed) {
        return false
      }
      return next()
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[AUTH_SETTLED]', e)
      return false
    }
  }
}




/**
 * @param {string | string[]} permissions
 */
const hasPermissions = (permissions) => instance.hasPermissions(permissions)

module.exports = {
  AUTH_EVENTS,
  AuthPlugin,
  decodeToken,
  hasPermissions,
  authGuard,
  authSettled,
  initialize,
  getUserAsync,
  Identity,
  setInstance,
  onAuthLoaded,
  requiresPermissions
}
