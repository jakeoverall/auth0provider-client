import { initialize } from '../lib'

const domain = ""
const clientId = ""
const audience = ""

export const AuthService = initialize({
  domain,
  clientId,
  audience,
  onRedirectCallback: appState => {
    window.location.replace(
      appState && appState.targetUrl
        ? appState.targetUrl
        : window.location.pathname
    )
  }
})

// Listen for secific AUTH_EVENTS hooks
AuthService.on(AuthService.AUTH_EVENTS.AUTHENTICATED, async () => {
  // AuthService.user is now defined
  const user = AuthService.user
  //Set bearer token on all requests
  // example: $resource.defaultHeaders.Authorization = AuthService.bearer
})