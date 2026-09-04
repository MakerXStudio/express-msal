import { IConfidentialClientApplication } from '@azure/msal-node'
import { Express, NextFunction, Request, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { AuthConfig, pkceAuthenticationMiddleware } from './index'

const createRequest = (): Request =>
  ({
    // cookie-session shape (isCookieSession) that is not yet authenticated, so the login handler runs
    session: { isChanged: false, isNew: true, isPopulated: false },
    originalUrl: '/some/page',
    protocol: 'https',
    hostname: 'api.example.com',
    headers: {},
    header: () => 'api.example.com',
  }) as unknown as Request

const createResponse = (): Response =>
  ({
    headersSent: false,
    redirect: vi.fn(),
    status: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    end: vi.fn(),
  }) as unknown as Response

const createMiddleware = (
  msalClient: IConfidentialClientApplication,
  authorizationUrlRequestOverride?: AuthConfig['authorizationUrlRequestOverride'],
) =>
  pkceAuthenticationMiddleware({
    app: { get: vi.fn() } as unknown as Express,
    msalClient,
    scopes: ['openid'],
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), verbose: vi.fn(), debug: vi.fn() },
    authorizationUrlRequestOverride,
  })

const AUTH_CODE_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test'

// run a login that reaches the redirect, and hand back the request the handler wrote its session to
const login = async (authorizationUrlRequestOverride?: AuthConfig['authorizationUrlRequestOverride']) => {
  const msalClient = { getAuthCodeUrl: vi.fn().mockResolvedValue(AUTH_CODE_URL) } as unknown as IConfidentialClientApplication
  const req = createRequest()
  const res = createResponse()

  createMiddleware(msalClient, authorizationUrlRequestOverride)(req, res, vi.fn() as NextFunction)

  await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith(AUTH_CODE_URL))
  return { req, msalClient }
}

describe('login handler', () => {
  it('responds 500 instead of crashing when login initiation fails', async () => {
    const msalClient = {
      getAuthCodeUrl: vi.fn().mockRejectedValue(new Error('Entra metadata fetch failed')),
    } as unknown as IConfidentialClientApplication
    const ensureAuthenticated = createMiddleware(msalClient)
    const res = createResponse()

    ensureAuthenticated(createRequest(), res, vi.fn() as NextFunction)

    // without the terminal .catch fix this rejection escapes the promise chain and takes the process down
    await vi.waitFor(() => expect(res.status).toHaveBeenCalledWith(500))
    expect(res.send).toHaveBeenCalledWith('Failed to initiate login')
    expect(res.redirect).not.toHaveBeenCalled()
  })

  it('redirects to the auth code URL when login initiation succeeds', async () => {
    const msalClient = {
      getAuthCodeUrl: vi.fn().mockResolvedValue(AUTH_CODE_URL),
    } as unknown as IConfidentialClientApplication
    const ensureAuthenticated = createMiddleware(msalClient)
    const res = createResponse()

    ensureAuthenticated(createRequest(), res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith(AUTH_CODE_URL))
    expect(res.status).not.toHaveBeenCalled()
  })

  it('carries an overridden authority on the session for the token leg to redeem at', async () => {
    const authority = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'
    const { req, msalClient } = await login(() => ({ authority }))

    expect(req.session).toMatchObject({ authority })
    // the authorize leg must still use it — this is where the code is minted
    expect(msalClient.getAuthCodeUrl).toHaveBeenCalledWith(expect.objectContaining({ authority }))
  })

  it('leaves authority off the session when the override names none', async () => {
    const { req } = await login(() => ({ prompt: 'select_account' }))

    // absent rather than present-and-undefined, so the session is exactly what 2.1.0 wrote
    expect(req.session).not.toHaveProperty('authority')
  })

  it('leaves authority off the session when there is no override', async () => {
    const { req } = await login()

    expect(req.session).not.toHaveProperty('authority')
  })
})
