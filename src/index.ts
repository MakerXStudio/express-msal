import {
  AuthenticationResult,
  AuthorizationCodeRequest,
  AuthorizationUrlRequest,
  IConfidentialClientApplication,
  Configuration,
  CryptoProvider,
  LogLevel,
} from '@azure/msal-node'
import { type Logger } from '@makerx/node-common'
import { Express, Request, RequestHandler } from 'express'

// implementation based on the official pkce sample:
// https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/samples/msal-node-samples/auth-code-pkce/src/index.ts

interface PKCECodes {
  challengeMethod: string
  challenge?: string
  verifier?: string
}

export type Session = Record<string, unknown>
type MaybeSession = Record<string, unknown> | null | undefined
type PKCEStartedSession = Session & { originalUrl: string; pkceCodes: PKCECodes; authority?: string }
export type AuthenticatedSession = Session & {
  isAuthenticated: true
  accessToken: string
}

const isCookieSession = (session: Session) => {
  return 'isChanged' in session && 'isNew' in session && 'isPopulated' in session
}
const isPKCEStartedSession = (session: MaybeSession): session is PKCEStartedSession => {
  return Boolean(session?.pkceCodes)
}
export const isAuthenticatedSession = (session: MaybeSession): session is AuthenticatedSession => {
  return session?.isAuthenticated === true
}

type AuthInput = Pick<AuthConfig, 'scopes' | 'logger'> & {
  msalClient: IConfidentialClientApplication
  authReplyRoute: string
  authorizationUrlRequestOverride?: AuthConfig['authorizationUrlRequestOverride']
}

const createEnsureAuthenticatedHandler = (input: AuthInput): RequestHandler => {
  const login = createLoginHandler(input)
  return (req, res, next) => {
    if (!req.session) throw Error('Express session is not available')
    if (!isCookieSession(req.session)) throw Error('Only cookie-session sessions are supported')
    if (isAuthenticatedSession(req.session)) return next()
    login(req, res, next)
  }
}

const PROXY_PATH = process.env.PROXY_PATH ?? ''
const createReplyUrl = (req: Request, replyRoute: string) => {
  // See https://expressjs.com/en/4x/api.html#req.hostname
  const hostAndPort = req.header('Host') ?? ''
  const reverseProxyAwareHost = req.hostname

  // Setting hostname does *not* change the port
  // See https://nodejs.org/docs/latest-v18.x/api/url.html#urlhostname
  const url = new URL(`${req.protocol}://${hostAndPort}${PROXY_PATH}${replyRoute}`)
  url.hostname = reverseProxyAwareHost

  return url.toString()
}

const createLoginHandler = ({ msalClient, scopes, authReplyRoute, authorizationUrlRequestOverride, logger }: AuthInput): RequestHandler => {
  const cryptoProvider = new CryptoProvider()

  return (req, res) => {
    cryptoProvider
      .generatePkceCodes()
      .then(async ({ verifier, challenge }) => {
        const pkceCodes: PKCECodes = {
          challengeMethod: 'S256',
          verifier,
          challenge,
        }

        const authorizationUrlRequest = authorizationUrlRequestOverride ? await Promise.resolve(authorizationUrlRequestOverride(req)) : {}

        req.session = {
          pkceCodes,
          originalUrl: `${PROXY_PATH}${req.originalUrl}`,
          // the code is minted at this authority, so it is also where it must be redeemed
          ...(authorizationUrlRequest.authority ? { authority: authorizationUrlRequest.authority } : {}),
        } as PKCEStartedSession

        return <AuthorizationUrlRequest>{
          scopes,
          ...authorizationUrlRequest,
          redirectUri: createReplyUrl(req, authReplyRoute),
          codeChallenge: pkceCodes.challenge,
          codeChallengeMethod: pkceCodes.challengeMethod,
        }
      })
      .then((authCodeUrlParameters) => msalClient.getAuthCodeUrl(authCodeUrlParameters))
      .then((response) => res.redirect(response))
      .catch((error: unknown) => {
        // rethrowing inside a terminal .catch becomes an unhandled promise rejection, which kills
        // the process — respond 500 instead, matching createAuthHandler's error handling
        logger?.error('Failed to initiate interactive login', { error })
        if (!res.headersSent) res.status(500).send('Failed to initiate login').end()
      })
  }
}

type CreateAuthHandlerInput = Pick<AuthConfig, 'scopes' | 'logger' | 'augmentSession'> & {
  msalClient: IConfidentialClientApplication
  authReplyRoute: string
}

const createAuthHandler = ({ msalClient, scopes, authReplyRoute, augmentSession, logger }: CreateAuthHandlerInput): RequestHandler => {
  return (req, res) => {
    if (!isPKCEStartedSession(req.session)) throw Error('Invalid session data for this (auth reply) route')

    const {
      originalUrl,
      authority,
      pkceCodes: { verifier },
    } = req.session

    if (req.query.error) {
      const details = { error: req.query.error, error_description: req.query.error_description }
      logger?.error('Error returned in auth reply query parameters', details)
      throw new Error(req.query.error as string, { cause: details })
    }

    const tokenRequest: AuthorizationCodeRequest = {
      code: req.query.code as string,
      scopes,
      redirectUri: createReplyUrl(req, authReplyRoute),
      codeVerifier: verifier,
      clientInfo: req.query.client_info as string,
      // redeem at the authority the code was minted at, not the client's own
      ...(authority ? { authority } : {}),
    }

    msalClient
      .acquireTokenByCode(tokenRequest)
      .then((response: AuthenticationResult | null) => {
        if (!response) {
          logger?.error('acquireTokenByCode did not return a response')
          return res.status(500).send('acquireTokenByCode did not return a response').end()
        }

        let session: AuthenticatedSession = {
          isAuthenticated: true,
          accessToken: response?.accessToken,
        }

        if (augmentSession) session = { ...session, ...augmentSession(response) }

        req.session = session
        res.redirect(originalUrl)

        if (logger) {
          const { authority, uniqueId, tenantId, scopes } = response
          logger?.info('User logged in via PCKE', { authority, uniqueId, tenantId, scopes })
        }
      })
      .catch((error: unknown) => {
        logger?.error('Failed to acquireTokenByCode', { error })
        res.status(500).send('acquireTokenByCode failed').end()
      })
  }
}

export const logout: RequestHandler = (req, res) => {
  req.session = null
  res.send('🙋🏽‍♀️').end()
}

// decode the JWT exp claim (no verification — that's the resource server's job);
// unparsable tokens pass through so downstream bearer verification decides
const sessionJwtIsExpired = ({ accessToken }: AuthenticatedSession): boolean => {
  try {
    const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString()) as { exp?: unknown }
    return typeof payload.exp === 'number' && payload.exp * 1000 <= Date.now()
  } catch {
    return false
  }
}

export const copySessionJwtToBearerHeader: RequestHandler = (req, _res, next) => {
  const session = req.session
  if (!!req.headers.authorization || !isAuthenticatedSession(session)) return next()
  // the session cookie can outlive the access token it carries — an expired token would fail
  // bearer verification downstream while its presence in the authorization header suppresses
  // interactive re-login, wedging the browser on 401s until the cookie expires. Drop the
  // session instead so the login middleware re-runs.
  if (sessionJwtIsExpired(session)) {
    req.session = null
    return next()
  }
  req.headers.authorization = `Bearer ${session.accessToken}`
  next()
}

export type AuthorizationUrlRequestOverridable = Partial<
  Omit<AuthorizationUrlRequest, 'redirectUri' | 'codeChallenge' | 'codeChallengeMethod'>
>

export interface AuthConfig {
  app: Express
  msalClient: IConfidentialClientApplication
  scopes: string[]
  authReplyRoute?: string
  augmentSession?: (response: AuthenticationResult) => Record<string, unknown> | undefined
  logger?: Logger
  authorizationUrlRequestOverride?: (req: Request) => AuthorizationUrlRequestOverridable | Promise<AuthorizationUrlRequestOverridable>
}

export const pkceAuthenticationMiddleware = ({
  app,
  msalClient,
  scopes,
  authReplyRoute = '/auth',
  augmentSession,
  logger,
  authorizationUrlRequestOverride,
}: AuthConfig): RequestHandler => {
  const ensureAuthenticated = createEnsureAuthenticatedHandler({
    msalClient,
    scopes,
    authReplyRoute,
    authorizationUrlRequestOverride,
    logger,
  })

  app.get(authReplyRoute, createAuthHandler({ msalClient, scopes, authReplyRoute, augmentSession, logger }))
  logger?.info(`Auth reply handler added to route ${authReplyRoute}`)

  return ensureAuthenticated
}

export enum NpmLogLevel {
  error = 0,
  warn = 1,
  info = 2,
  http = 3,
  verbose = 4,
  debug = 5,
  silly = 6,
}

export const toNpmLogLevel = (level: LogLevel): keyof typeof NpmLogLevel => {
  switch (level) {
    case LogLevel.Error:
      return 'error'
    case LogLevel.Warning:
      return 'warn'
    case LogLevel.Info:
      return 'info'
    case LogLevel.Verbose:
      return 'verbose'
    case LogLevel.Trace:
      return 'debug'
  }
}

export { Configuration, AuthenticationResult }
