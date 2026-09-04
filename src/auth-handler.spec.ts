import { IConfidentialClientApplication } from '@azure/msal-node'
import { Express, NextFunction, Request, RequestHandler, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { pkceAuthenticationMiddleware } from './index'

const createRequest = (session: Record<string, unknown>): Request =>
  ({
    session,
    query: { code: 'auth-code' },
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

const pkceStartedSession = (authority?: string) => ({
  originalUrl: '/some/page',
  pkceCodes: { challengeMethod: 'S256', verifier: 'the-verifier' },
  ...(authority ? { authority } : {}),
})

// the reply handler is not exported — reach it via the app.get registration pkceAuthenticationMiddleware makes
const createAuthHandler = (msalClient: IConfidentialClientApplication) => {
  const get = vi.fn()
  pkceAuthenticationMiddleware({
    app: { get } as unknown as Express,
    msalClient,
    scopes: ['openid'],
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), verbose: vi.fn(), debug: vi.fn() },
  })
  return get.mock.calls[0][1] as RequestHandler
}

const createTokenClient = () =>
  ({
    acquireTokenByCode: vi.fn().mockResolvedValue({ accessToken: 'an-access-token' }),
  }) as unknown as IConfidentialClientApplication

describe('auth handler', () => {
  it('redeems the code at the authority the session carries', async () => {
    const authority = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'
    const msalClient = createTokenClient()
    const res = createResponse()

    createAuthHandler(msalClient)(createRequest(pkceStartedSession(authority)), res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith('/some/page'))
    expect(msalClient.acquireTokenByCode).toHaveBeenCalledWith(expect.objectContaining({ authority }))
  })

  it('leaves the client authority in force when the session carries none', async () => {
    const msalClient = createTokenClient()
    const res = createResponse()

    createAuthHandler(msalClient)(createRequest(pkceStartedSession()), res, vi.fn() as NextFunction)

    await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith('/some/page'))
    // a session written by an earlier version has no authority — the request must look exactly as it did then
    expect(msalClient.acquireTokenByCode).toHaveBeenCalledWith(expect.not.objectContaining({ authority: expect.anything() }))
  })
})
