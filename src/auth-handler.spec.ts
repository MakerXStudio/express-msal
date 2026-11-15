import { AuthorizationCodeRequest, IConfidentialClientApplication } from '@azure/msal-node'
import { Express, NextFunction, Request, RequestHandler, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { openValue, pkceAuthenticationMiddleware, sealValue } from './index'

const SECRET = 'the-cookie-secret'

const createRequest = (authority?: string, verifier = 'the-verifier'): Request =>
  ({
    session: {
      originalUrl: '/some/page',
      pkceCodes: { challengeMethod: 'S256', verifier },
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
const createAuthHandler = (sessionSecret?: string) => {
  const acquireTokenByCode = vi.fn().mockResolvedValue({ accessToken: 'an-access-token' })
  const get = vi.fn()

  pkceAuthenticationMiddleware({
    app: { get } as unknown as Express,
    msalClient: { acquireTokenByCode } as unknown as IConfidentialClientApplication,
    scopes: ['openid'],
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), verbose: vi.fn(), debug: vi.fn() },
    sessionSecret,
  })
  return { authHandler: get.mock.calls[0][1] as RequestHandler, acquireTokenByCode }
}

const reply = async (authority?: string, sessionSecret?: string, verifier?: string) => {
  const { authHandler, acquireTokenByCode } = createAuthHandler(sessionSecret)
  const req = createRequest(authority, verifier)
  const res = createResponse()
  authHandler(req, res, vi.fn() as NextFunction)

  await vi.waitFor(() => expect(res.redirect).toHaveBeenCalledWith('/some/page'))
  return { tokenRequest: acquireTokenByCode.mock.calls[0][0] as AuthorizationCodeRequest, session: req.session as { accessToken: string } }
}

describe('auth handler', () => {
  it('redeems the code at the authority the session carries', async () => {
    const authority = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'

    expect((await reply(authority)).tokenRequest).toMatchObject({ authority })
  })

  it('leaves the client authority in force when the session carries none', async () => {
    // a session written by 2.1.0 has no authority. Assert the key is absent rather than
    // present-and-undefined, so the token request is exactly what 2.1.0 sent.
    expect((await reply()).tokenRequest).not.toHaveProperty('authority')
  })

  it('opens the sealed verifier, and seals the access token, when sessionSecret is set', async () => {
    const { tokenRequest, session } = await reply(undefined, SECRET, sealValue('the-verifier', SECRET))

    expect(tokenRequest.codeVerifier).toBe('the-verifier')
    expect(session.accessToken).toMatch(/^enc:v1:/)
    expect(openValue(session.accessToken, SECRET)).toBe('an-access-token')
  })

  it('stores the plain access token when sessionSecret is not set', async () => {
    expect((await reply()).session.accessToken).toBe('an-access-token')
  })

  it.each([
    ['a plain verifier', 'the-verifier'],
    ['a verifier sealed with another secret', sealValue('the-verifier', 'another-secret')],
  ])('rejects %s when sessionSecret is set, as it rejects an invalid session', (_, verifier) => {
    const { authHandler, acquireTokenByCode } = createAuthHandler(SECRET)

    expect(() => authHandler(createRequest(undefined, verifier), createResponse(), vi.fn() as NextFunction)).toThrow(
      'Invalid session data for this (auth reply) route',
    )
    expect(acquireTokenByCode).not.toHaveBeenCalled()
  })
})
