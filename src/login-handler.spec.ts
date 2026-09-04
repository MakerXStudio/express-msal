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

const createRedirectingClient = () =>
  ({
    getAuthCodeUrl: vi.fn().mockResolvedValue('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test'),
  }) as unknown as IConfidentialClientApplication

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
    const authCodeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test'
    const msalClient = {
      getAuthCodeUrl: vi.fn().mockResolvedValue(authCodeUrl),
    } as unknown as IConfidentialClientApplication
    const ensureAuthenticated = createMiddleware(msalClient)
    const res = createResponse()

    ensureAuthenticated(createRequest(), res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith(authCodeUrl))
    expect(res.status).not.toHaveBeenCalled()
  })

  it('carries an overridden authority on the session for the token leg to redeem at', async () => {
    const authority = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'
    const msalClient = createRedirectingClient()
    const ensureAuthenticated = createMiddleware(msalClient, () => ({ authority }))
    const req = createRequest()
    const res = createResponse()

    ensureAuthenticated(req, res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalled())
    // the code is minted at this authority, so the reply handler must redeem it there
    expect(req.session).toMatchObject({ authority })
    // ...and the authorize leg still uses it
    expect(msalClient.getAuthCodeUrl).toHaveBeenCalledWith(expect.objectContaining({ authority }))
  })

  it('leaves authority off the session when the override names none', async () => {
    const ensureAuthenticated = createMiddleware(createRedirectingClient(), () => ({ prompt: 'select_account' }))
    const req = createRequest()
    const res = createResponse()

    ensureAuthenticated(req, res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalled())
    // absent rather than undefined, so cookie-session does not serialise a dead key
    expect(req.session).not.toHaveProperty('authority')
  })

  it('leaves authority off the session when there is no override', async () => {
    const ensureAuthenticated = createMiddleware(createRedirectingClient())
    const req = createRequest()
    const res = createResponse()

    ensureAuthenticated(req, res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalled())
    expect(req.session).not.toHaveProperty('authority')
  })
})
