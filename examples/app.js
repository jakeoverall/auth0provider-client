import { initialize } from '../lib'

const domain = ''
const clientId = ''

export const AuthService = initialize({
  domain,
  clientId,
  authorizationParams: {
    redirect_uri: window.location.href
  }
})



// Listen for secific AUTH_EVENTS hooks
AuthService.on(AuthService.AUTH_EVENTS.AUTHENTICATED, async () => {
  // AuthService.user is now defined
  const identity = AuthService.identity
  // Set bearer token on all requests
  // example: $resource.defaultHeaders.Authorization = AuthService.bearer
})
