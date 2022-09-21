# Express MSAL

Simple server-side cookie-session based Azure AD authentication for Express.js apps.

## What does this do?

This library wraps [@azure/msal-node](https://www.npmjs.com/package/@azure/msal-node) to provide a simple way to run interactive authentication on Express JS hosted UIs (web pages) that need to call APIs using Bearer token authentication, without writing and deploying client-side MSAL code.

As an example use case, we host GraphQL Playground or Apollo Sandbox and Voyager UIs alongside our GraphQL APIs from server-side middleware. This package allows us to add authentication across all those UIs without building, packaging and deploying custom UI code.

For Bearer token authentication, see [@makerxstudio/express-bearer](https://github.com/MakerXStudio/express-bearer).

## Usage

```
npm install @azure/msal-node express cookie-session @makerxstudio/express-msal
```

```ts
import { PublicClientApplication } from '@azure/msal-node'
import { AuthConfig, pkceAuthenticationMiddleware, copySessionJwtToBearerHeader } from '@makerxstudio/express-msal'
import cookieSession from 'cookie-session'

const app = express()
app.use(cookieSession(cookieSessionOptions))

const msalApp = new PublicClientApplication(msalConfig)
const authConfig: AuthConfig = {
  app,
  msalApp,
  scopes: ['profile', 'api://my-api/.default'],
}

// trigger pkce auth on GET requests (iteractive users accessing UIs)
app.get(pkceAuthenticationMiddleware(authConfig))
// set a Bearer {token} auth header on POST request to '/graphql'
app.post('/graphql', copySessionJwtToBearerHeader)
```

- `pkceAuthenticationMiddleware` starts the PKCE auth flow (redirect) when there is no session, creates a cookie-session containing an accessToken.
- `copySessionJwtToBearerHeader`: takes the accessToken from the session cookie and adds a Bearer {token} header onto the request, useful for supporting API access from your session-basedd auth

## Is this secure?

We only use cookie-session with this library, along with secure-as-possible cookie configuration.

The logic here is that access tokens are already persisted in browser storage and are freely available in the browser, however it's definitely possible to configure an insecure session cookie that does not restrict access to the cookie and access token adequately.

We strongly recommend configuring your [cookie-session options](https://github.com/expressjs/cookie-session#options) carefully, applying the most restrictive policy, setting `path`, `domain`, `sameSite`, `secure`, `httpOnly` etc.

```ts
const cookieSessionOptions = {
  name: '<session-name>',
  maxAge: 1000 * 60 * 60,
  sameSite: 'strict',
  secure: true,
  httpOnly: true,
}
app.use(cookieSession(cookieSessionOptions))
```

## Config

`AuthConfig`:

| Option           | Description                                                                                                                               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `app`            | The Express JS app on which the auth reply handler is set up (see `authReplyRoute`).                                                      |
| `msalClient`     | The `@azure/msal-node` `ClientApplication` instance, either a `PublicClientApplication` or `ConfidentialClientApplication` (e.g. for B2C) |
| `scopes`         | The scopes to use to aquire the accessToken.                                                                                              |
| `authReplyRoute` | The route on which the auth completion handler is be set up, which must be configured in the Azure App Registration, default: `/auth`.    |
| `augmentSession` | Optional function to add additional info to the session from the msal `AuthenticationResult`.                                             |
| `logger`         | Optional logger implementation to log token validation errors, handler setup info entry etc.                                              |

## Detailed usage examples

```ts
// set up cookie-session
const cookieSessionOptions = {
  name: '<session-name>',
  maxAge: 1000 * 60 * 60, // match session lifetime to the access token
  sameSite: 'strict',
  secure: true,
  httpOnly: true,
}
app.use(cookieSession(cookieSessionOptions))

// set up msal client (use ConfidentialClientApplication for B2C)
const msalApp = new PublicClientApplication({
  auth: {
    clientId: '<client ID>',
    authority: 'https://login.microsoftonline.com/<tenant ID>',
  },
})

// configure all config options
const authConfig: AuthConfig = {
  app,
  msalApp,
  scopes: ['profile', 'api://my-api/.default'],
  // specify non-default reply url
  replyUrl: '/auth-callback',
  // add some additional info to the session from the msal `AuthenticationResult`
  augmentSession: (response) => {
    return { username: response.account?.username }
  },
  // specify a logger
  logger,
}

// use pkce auth on everything apart from ./api*
app.use(/^\/(?!api).*/, pkceAuthenticationMiddleware(authConfig))

// set a Bearer {token} auth header on request to '/api*
app.use('/api*', copySessionJwtToBearerHeader)

// add a logout endpoint for GET requests to /logout
app.get('/logout', logout)

// return the currently logger in user's username from GET requests to /user
app.get('/user', (req, res) => {
  if (!isAuthenticatedSession(req.session)) return res.status(400).send('Not logged in').end()
  res.send(req.session.username).end()
})
```

### Logging

Set the logger implementation to an object that fulfills the `Logger` definition:

```ts
type Logger = {
  error(message: string, ...optionalParams: unknown[]): void
  warn(message: string, ...optionalParams: unknown[]): void
  info(message: string, ...optionalParams: unknown[]): void
  verbose(message: string, ...optionalParams: unknown[]): void
  debug(message: string, ...optionalParams: unknown[]): void
}
```

Note: this type is compatible with [winston loggers](https://github.com/winstonjs/winston).

The following example uses console logging:

```ts
const logger: Logger = {
  error: (message: string, ...params: unknown[]) => console.error
  warn: (message: string, ...params: unknown[]) => console.warn
  info: (message: string, ...params: unknown[]) => console.info
  verbose: (message: string, ...params: unknown[]) => console.trace
  debug: (message: string, ...params: unknown[]) => console.debug
}

const pkceAuthConfig: AuthConfig = {
  /* other config */
  logger,
}
```

#### @azure/msal-node

Use the MSAL system loggerOptions config to control logging from the @azure/msal package:

```ts
const config: Partial<Configuration> = {
  system: {
    loggerOptions: {
      loggerCallback(loglevel: LogLevel, message: string, containsPii: boolean) {
        console.log(message)
      },
      piiLoggingEnabled: false,
      logLevel: LogLevel.Verbose,
    },
  },
}
```

To assist supplying a log function to MSAL, this module exports `toNpmLogLevel` which maps MSAL `LogLevel` values to [npm log level labels](https://github.com/winstonjs/winston#logging-levels), making it easy to integrate a winston `Logger` instance:

```ts
const msalLoggerConfig: Partial<Configuration> = {
  system: {
    loggerOptions: {
      loggerCallback: (level, message) => logger.log(toNpmLogLevel(level), message),
    },
  },
}
```
