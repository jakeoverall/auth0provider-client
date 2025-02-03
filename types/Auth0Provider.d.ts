export namespace AUTH_EVENTS {
    let LOADING: string;
    let LOADED: string;
    let AUTHENTICATED: string;
    let TOKEN_CHANGE: string;
}
export class AuthPlugin {
    /**
     *
     * @param {auth0.Auth0ClientOptions} options
     */
    constructor(options: auth0.Auth0ClientOptions);
    _listeners: {};
    _state: string;
    /**
     * @param {string} val
     */
    set state(val: string);
    get state(): string;
    /**
     * @type {Identity}
     */
    identity: Identity;
    bearer: string;
    popupOpen: boolean;
    /** @type {auth0.Auth0Client} */
    auth0Client: auth0.Auth0Client;
    error: any;
    options: auth0.Auth0ClientOptions;
    /**
     * @param {string | number} event
     * @param {function} fn
     * @param {any} thisContext
     */
    on(event: string | number, fn: Function, thisContext?: any): void;
    /**
     * @param {string | number} event
     * @param {function} fn
     */
    off(event: string | number, fn: Function): void;
    /**
     * @param {string} event
     * @param {any} [payload]
     */
    emit(event: string, payload?: any): void;
    /** Authenticates the user using a popup window
     * @param {auth0.PopupLoginOptions} [o]
    */
    loginWithPopup(o?: auth0.PopupLoginOptions): Promise<void>;
    /** Handles the callback when logging in using a redirect */
    handleRedirectCallback(): Promise<void>;
    /** Authenticates the user using the redirect method
     * @param {auth0.RedirectLoginOptions} [o]
    */
    loginWithRedirect(o?: auth0.RedirectLoginOptions): Promise<void>;
    /**
   * Returns the access token. If the token is invalid or missing, a new one is retrieved
   * @param {auth0.GetTokenSilentlyOptions} [o]
   */
    getTokenSilently(o?: auth0.GetTokenSilentlyOptions): Promise<string>;
    /**
   * @param {string[] | string} permissions
   */
    hasPermissions(permissions: string[] | string): boolean;
    /**
    * @param {string} token
    */
    getIdentityClaims(token: string): Promise<Identity>;
    /**
    * Gets the access token using a popup window
    * @param {auth0.GetTokenWithPopupOptions} [o]
    */
    getTokenWithPopup(o?: auth0.GetTokenWithPopupOptions): Promise<string>;
    getUserData(): Promise<void>;
    /** Logs the user out and removes their session on the authorization server
     * @param {auth0.LogoutOptions} [o]
    */
    logout(o?: auth0.LogoutOptions): Promise<void>;
    verifyAuth0(): AuthPlugin;
    /**
   * Use this lifecycle method to instantiate the SDK client
   * @param {auth0.Auth0ClientOptions} options
   */
    createAuthInstance(options: auth0.Auth0ClientOptions): Promise<void>;
}
export function decodeToken(str?: string): string;
/**
 * @param {string | string[]} permissions
 */
export function hasPermissions(permissions: string | string[]): boolean;
/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
export function authGuard(to: {
    fullPath: any;
}, from: any, next: () => any): Promise<any>;
/**
* @param {{ fullPath: any; }} to
* @param {any} from
* @param {() => any} next
*/
export function authSettled(to: {
    fullPath: any;
}, from: any, next: () => any): Promise<any>;
/**
 * @param {auth0.Auth0ClientOptions} options
 */
export function initialize(options: auth0.Auth0ClientOptions): AuthPlugin;
export function getUserAsync(): Promise<Identity>;
/**
 * Identity is a class that represents the user's identity claims granted from auth0
 */
export class Identity {
    constructor(data: any);
    /**
     * Audience - Who or what the token is intended for
     * @type {string[]}
     */
    aud: string[];
    /**
     * The Authorized Party - the party to which the ID Token was issued
     * @type {string}
     * */
    azp: string;
    /**
     * The user's email address
     * @type {string}
     * */
    email: string;
    /**
     * Has the user's email been verified
     * @type {boolean}
     * */
    email_verified: boolean;
    /**
     * Expiration time of the token
     * @type {number}
     * */
    exp: number;
    /**
     * Issued At - the time at which the token was issued
     * @type {number}
     * */
    iat: number;
    /**
     * Issuer - the party that issued the token
     * @type {string}
     * */
    iss: string;
    /**
     * The user's name
     * @type {string}
     * */
    name: string;
    /**
     * The user's set of permissions if included
     * @type {string[]}
     * */
    permissions: string[];
    /**
     * The user's picture url
     * @type {string}
     * */
    picture: string;
    /**
     * The scopes granted to the token
     * @type {string}
     * */
    scope: string;
    /**
     * The user's subject identifier - a unique identifier for the user
     * @type {string}
     * */
    sub: string;
    /**
     * The last time the token was updated
     * @type {string}
     * */
    updated_at: string;
}
/**
 * @param {AuthPlugin|any} newInstance
 * Useful for testing
 * */
export function setInstance(newInstance: AuthPlugin | any): void;
export function onAuthLoaded(cb: any): Promise<any>;
/**
 *
 * @param {String | String[]} permissions
 * @returns
 */
export function requiresPermissions(permissions?: string | string[]): (to: any, from: any, next: any) => Promise<any>;
import auth0 = require("@auth0/auth0-spa-js");
