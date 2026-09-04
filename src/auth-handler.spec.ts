import { AuthorizationCodeRequest, IConfidentialClientApplication } from '@azure/msal-node'
import { Express, NextFunction, Request, RequestHandler, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { pkceAuthenticationMiddleware } from './index'

const createRequest = (authority?: string): Request =>
  ({
    session: {
      originalUrl: '/some/page',
      pkceCodes: { challengeMethod: 'S256', verifier: 'the-verifier' },
      ...(authority ? { authority } : {}),
    },
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

// the reply handler is not exported — reach it via the app.get registration pkceAuthenticationMiddleware makes,
// then run it against a session the login handler would have written
const reply = async (authority?: string) => {
  const acquireTokenByCode = vi.fn().mockResolvedValue({ accessToken: 'an-access-token' })
  const get = vi.fn()
  const res = createResponse()

  pkceAuthenticationMiddleware({
    app: { get } as unknown as Express,
    msalClient: { acquireTokenByCode } as unknown as IConfidentialClientApplication,
    scopes: ['openid'],
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), verbose: vi.fn(), debug: vi.fn() },
  })
  const authHandler = get.mock.calls[0][1] as RequestHandler
  authHandler(createRequest(authority), res, vi.fn() as NextFunction)

  await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith('/some/page'))
  return acquireTokenByCode.mock.calls[0][0] as AuthorizationCodeRequest
}

describe('auth handler', () => {
  it('redeems the code at the authority the session carries', async () => {
    const authority = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'

    expect(await reply(authority)).toMatchObject({ authority })
  })

  it('leaves the client authority in force when the session carries none', async () => {
    // a session written by 2.1.0 has no authority. Assert the key is absent rather than
    // present-and-undefined, so the token request is exactly what 2.1.0 sent.
    expect(await reply()).not.toHaveProperty('authority')
  })
})
