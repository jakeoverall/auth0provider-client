import createAuth0Client from '@auth0/auth0-spa-js'
import { EventEmitter } from './EventEmitter'

/** Define a default action to perform after authentication */
const DEFAULT_REDIRECT_CALLBACK = () =>
  window.history.replaceState({}, document.title, window.location.pathname)

/**
 @type {AuthPlugin}
 */
let instance

export class AuthPlugin extends EventEmitter {
  constructor(options = {}) {
    if (instance) { return instance }
    super()
    instance = this
    this.AUTH_EVENTS = {
      LOADING: 'LOADING',
      LOADED: 'LOADED',
      AUTHENTICATED: 'AUTHENTICATED',
      TOKEN_CHANGE: 'TOKEN_CHANGE'
    }
    this.options = options
    this.options.onRedirectCallback = this.options.onRedirectCallback || DEFAULT_REDIRECT_CALLBACK
    this.loading = true
    this.isAuthenticated = false
    this.user = {}
    this.userInfo = {}
    this.identity = {}
    this.bearer = ''
    this.auth0Client = null
    this.popupOpen = false
    this.error = null
    this.created(options)
    return instance
  }

  /** Authenticates the user using a popup window */
  async loginWithPopup(o = {
    returnTo: window.location.origin
  }) {
    this.popupOpen = true

    try {
      await this.auth0Client.loginWithPopup(o)
      this.user = await this.auth0Client.getUser()
      await this.getUserData()
      this.isAuthenticated = true
    } catch (e) {
      // eslint-disable-next-line
      console.error(e);
    } finally {
      this.popupOpen = false
    }
  }

  /** Handles the callback when logging in using a redirect */
  async handleRedirectCallback() {
    this.loading = true
    try {
      await this.auth0Client.handleRedirectCallback()
      this.user = await this.auth0Client.getUser()
      await this.getUserData()
      this.isAuthenticated = true
    } catch (e) {
      this.error = e
    } finally {
      this.loading = false
    }
  }

  /** Authenticates the user using the redirect method */
  loginWithRedirect(o = {}) {
    if (!o.appState) {
      o.redirectUri = o.redirectUri || window.location.href
    }
    return this.auth0Client.loginWithRedirect(o)
  }

  /**
   * Returns all the claims present in the ID token
   * @param {import("@auth0/auth0-spa-js").GetIdTokenClaimsOptions} o
   */
  getIdTokenClaims(o) {
    return this.auth0Client.getIdTokenClaims(o)
  }

  /**
   * Returns the access token. If the token is invalid or missing, a new one is retrieved
   * @param {AuthServiceMethodOptions} [o]
   */
  async getTokenSilently(o) {
    const token = await this.auth0Client.getTokenSilently(o)
    this.getIdentityClaims(token)
    this.emit(this.AUTH_EVENTS.TOKEN_CHANGE, this)
    return token
  }

  /**
   * @param {string[] | string} permissions
   */
  hasPermissions(permissions) {
    if (!Array.isArray(permissions)) {
      permissions = [permissions]
    }
    if (!this.identity.permissions) {
      return false
    }
    while (permissions.length) {
      const next = permissions.pop()
      const /**
         * @param {any} p
         */
        found = this.identity.permissions.find(p => p === next)
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
    if (!this.userInfo.roles) {
      return false
    }
    while (roles.length) {
      const next = roles.pop()
      const /**
         * @param {any} r
         */
        found = this.userInfo.roles.find(r => r === next)
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
    this.identity = JSON.parse(decodeToken(token))
    return this.identity
  }

  /**
   * Gets the access token using a popup window
   * @param {AuthServiceMethodOptions} o
   */
  async getTokenWithPopup(o) {
    const token = await this.auth0Client.getTokenWithPopup(o)
    this.getIdentityClaims(token)
    this.emit(this.AUTH_EVENTS.TOKEN_CHANGE, this)
    return token
  }

  async getUserData() {
    try {
      const token = await this.getTokenSilently()
      await this.getIdentityClaims(token)
      this.bearer = 'Bearer ' + token
      // eslint-disable-next-line no-undef
      const res = await fetch(`https://${this.options.domain}/userinfo`, {
        headers: {
          authorization: this.bearer
        }
      })

      const userData = await res.json()
      for (const key in userData) {
        let keep = key
        if (key.includes('https')) {
          keep = keep.slice(keep.lastIndexOf('/') + 1)
        }
        this.userInfo[keep] = userData[key]
      }
      this.user.isAuthenticated = true
      this.emit(this.AUTH_EVENTS.AUTHENTICATED, this)
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[AUTH0-PROVIDER-ERROR] unable to retrieve user data', e)
    }
  }

  /** Logs the user out and removes their session on the authorization server */
  logout(o = {
    returnTo: window.location.origin
  }) {
    const logout = this.auth0Client.logout(o)
    this.bearer = ''
    this.user = {}
    this.userInfo = {}
    this.identity = {}
    this.isAuthenticated = false
    return logout
  }

  /**
   * Use this lifecycle method to instantiate the SDK client
   * @param {{ domain?: any; clientId?: any; audience?: any; redirectUri?: any; onRedirectCallback?: any; useRefreshTokens?:boolean }} options
   */
  async created(options) {
    this.emit(this.AUTH_EVENTS.LOADING)
    // Create a new instance of the SDK client using members of the given options object
    this.auth0Client = await createAuth0Client({
      domain: options.domain,
      client_id: options.clientId,
      audience: options.audience,
      redirect_uri: options.redirectUri || window.location.origin,
      useRefreshTokens: options.useRefreshTokens || false
    })

    try {
      // If the user is returning to the app after authentication..
      if (
        window.location.search.includes('code=') &&
        window.location.search.includes('state=')
      ) {
        // handle the redirect and retrieve tokens
        const { appState } = await this.auth0Client.handleRedirectCallback()

        // Notify subscribers that the redirect callback has happened, passing the appState
        // (useful for retrieving any pre-authentication state)
        options.onRedirectCallback(appState)
      }
    } catch (e) {
      this.error = e
    } finally {
      // Initialize our internal authentication state
      this.isAuthenticated = await this.auth0Client.isAuthenticated()
      this.user = await this.auth0Client.getUser()
      await this.getUserData()
      this.loading = false
      this.emit(this.AUTH_EVENTS.LOADED)
    }
  }
}

export const onAuthLoaded = cb => {
  return new Promise((resolve, reject) => {
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

function b64DecodeUnicode(str = '.') {
  try {
    return decodeURIComponent(
      // eslint-disable-next-line no-undef
      atob(str).replace(/(.)/g, function(m, p) {
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
export function decodeToken(str = '.') {
  try {
    str = str.split('.')[1]
    let output = str.replace(/-/g, '+').replace(/_/g, '/')
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
 * @param {{ onRedirectCallback: () => void; domain: string, audience: string, clientId: string, useRefreshTokens?: boolean  }} options
 * @returns { AuthPlugin } AuthPlugin
 */
export function initialize(options) { return new AuthPlugin(options) }

/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
export async function authGuard(to, from, next) {
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
export async function authSettled(to, from, next) {
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
export const hasPermissions = (permissions) => instance.hasPermissions(permissions)
/**
 * @param {string | string[]} roles
 */
export const hasRoles = (roles) => instance.hasPermissions(roles)

/**
 * @typedef {{
 * display?: 'page' | 'popup' | 'touch' | 'wap',
 * prompt?: 'none' | 'login' | 'consent' | 'select_account',
 * max_age?: string | number  ,
 * ui_locales?: string,
 * id_token_hint?: string,
 * login_hint?: string,
 * acr_values?: string,
 * scope?: string,
 * audience?: string,
 * connection?: string,
 * [key: string]: any
 * }} AuthServiceMethodOptions
 */
