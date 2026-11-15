import { AuthorizationCodeRequest, AuthorizationUrlRequest, IConfidentialClientApplication } from '@azure/msal-node'
import cookieSession from 'cookie-session'
import express from 'express'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { AuthConfig, createCopySessionJwtToBearerHeader, pkceAuthenticationMiddleware } from './index'

const COOKIE_SECRET = 'the-cookie-secret'
const AUTHORIZE_URL = 'https://login.example.com/authorize'

const base64url = (value: string | Buffer) => Buffer.from(value).toString('base64url')

// An Entra ID access token of about 2.5 KB: claims in the shape Entra ID writes, with group IDs to
// fill the payload, and an RS256 signature of 256 random bytes
const createAccessToken = () => {
  const header = { typ: 'JWT', alg: 'RS256', kid: randomBytes(20).toString('base64url') }
  const payload = {
    aud: 'api://my-api',
    iss: `https://sts.windows.net/${randomUUID()}/`,
    iat: Math.floor(Date.now() / 1000),
    nbf: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: 'Example User',
    oid: randomUUID(),
    preferred_username: 'example.user@example.com',
    scp: 'access_as_user',
    sub: randomBytes(32).toString('base64url'),
    tid: randomUUID(),
    uti: randomBytes(16).toString('base64url'),
    ver: '2.0',
    groups: Array.from({ length: 30 }, () => randomUUID()),
  }
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.${base64url(randomBytes(256))}`
}

const ACCESS_TOKEN = createAccessToken()

// one Express app with a real cookie-session, mounted as the README describes
const createApp = (sessionSecret?: AuthConfig['sessionSecret']) => {
  const msalClient = {
    getAuthCodeUrl: vi.fn((request: AuthorizationUrlRequest) =>
      Promise.resolve(`${AUTHORIZE_URL}?code_challenge=${request.codeChallenge}`),
    ),
    acquireTokenByCode: vi.fn((_: AuthorizationCodeRequest) => Promise.resolve({ accessToken: ACCESS_TOKEN })),
  }
  const app = express()
  app.use(cookieSession({ name: 'session', secret: COOKIE_SECRET }))

  const ensureAuthenticated = pkceAuthenticationMiddleware({
    app,
    msalClient: msalClient as unknown as IConfidentialClientApplication,
    scopes: ['openid'],
    sessionSecret,
  })
  app.use(createCopySessionJwtToBearerHeader({ sessionSecret }))
  app.get('/*splat', (req, res, next) => (req.headers.authorization ? next() : ensureAuthenticated(req, res, next)))
  app.get('/page', (req, res) => {
    res.send(req.headers.authorization)
  })

  const server = app.listen(0)
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  return { msalClient, server, baseUrl }
}

type App = ReturnType<typeof createApp>

const get = (app: App, path: string, cookies: string[] = []) =>
  fetch(`${app.baseUrl}${path}`, { redirect: 'manual', headers: { cookie: cookies.join('; ') } })

// the `name=value` pairs of the Set-Cookie headers, to send back on the next request
const cookiesOf = (response: Response) => response.headers.getSetCookie().map((header) => header.split(';')[0])

const decodedSession = (cookies: string[]) => {
  const value = cookies.find((cookie) => cookie.startsWith('session='))!.slice('session='.length)
  return Buffer.from(value, 'base64').toString('utf8')
}

// sign in through the app: the login redirect, then the auth reply
const signIn = async (app: App) => {
  const loginResponse = await get(app, '/page')
  const loginCookies = cookiesOf(loginResponse)
  const replyResponse = await get(app, '/auth?code=the-code', loginCookies)
  return { loginResponse, loginCookies, replyResponse, sessionCookies: cookiesOf(replyResponse) }
}

describe('a sealed session, with a real cookie-session', () => {
  let sealedApp: App
  let plainApp: App

  beforeAll(() => {
    sealedApp = createApp(COOKIE_SECRET)
    plainApp = createApp()
  })

  afterAll(() => {
    sealedApp.server.close()
    plainApp.server.close()
  })

  it('keeps the verifier and the token out of the decoded cookie', async () => {
    const { loginCookies, replyResponse, sessionCookies } = await signIn(sealedApp)
    const tokenRequest = sealedApp.msalClient.acquireTokenByCode.mock.calls[0][0]
    const { codeChallenge } = sealedApp.msalClient.getAuthCodeUrl.mock.calls[0][0]

    expect(replyResponse.status).toBe(302)
    expect(replyResponse.headers.get('location')).toBe('/page')
    // the reply opened the verifier that the login sealed
    expect(createHash('sha256').update(tokenRequest.codeVerifier!).digest('base64url')).toBe(codeChallenge)
    expect(decodedSession(loginCookies)).not.toContain(tokenRequest.codeVerifier)
    expect(decodedSession(sessionCookies)).not.toContain(ACCESS_TOKEN.split('.')[1])
    expect(decodedSession(sessionCookies)).not.toMatch(/eyJ/)
  })

  it('keeps the cookie of a 2.5 KB token under the 4,096-byte browser limit', async () => {
    const { sessionCookies } = await signIn(sealedApp)
    const sessionCookie = sessionCookies.find((cookie) => cookie.startsWith('session='))!

    expect(ACCESS_TOKEN.length).toBeGreaterThanOrEqual(2500)
    expect(sessionCookie.length).toBeLessThan(4096)
  })

  it('copies the plain token on a later request, and sets no cookie', async () => {
    const { sessionCookies } = await signIn(sealedApp)
    const response = await get(sealedApp, '/page', sessionCookies)

    expect(response.status).toBe(200)
    expect(await response.text()).toBe(`Bearer ${ACCESS_TOKEN}`)
    expect(response.headers.getSetCookie()).toEqual([])
  })

  it('starts a new sign-in for a cookie with a plain token from before the upgrade', async () => {
    const { sessionCookies } = await signIn(plainApp)
    expect(decodedSession(sessionCookies)).toContain(ACCESS_TOKEN)

    const response = await get(sealedApp, '/page', sessionCookies)

    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toMatch(new RegExp(`^${AUTHORIZE_URL}`))
  })
})
