import { NextFunction, Request, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { AuthConfig, copySessionJwtToBearerHeader, createCopySessionJwtToBearerHeader } from './index'

const jwtWithExp = (exp: number) =>
  `${Buffer.from('{}').toString('base64')}.${Buffer.from(JSON.stringify({ exp })).toString('base64')}.signature`

const secondsFromNow = (seconds: number) => Math.floor(Date.now() / 1000) + seconds

const run = (session: Request['session'], authorization?: string) => {
  const req = { headers: { authorization }, session } as unknown as Request
  const next = vi.fn()
  copySessionJwtToBearerHeader(req, {} as Response, next as NextFunction)
  expect(next).toHaveBeenCalledOnce()
  return req
}

describe('copySessionJwtToBearerHeader', () => {
  it('copies an unexpired session token to the authorization header', () => {
    const accessToken = jwtWithExp(secondsFromNow(60))
    const req = run({ isAuthenticated: true, accessToken })
    expect(req.headers.authorization).toBe(`Bearer ${accessToken}`)
    expect(req.session).not.toBeNull()
  })

  it('drops the session and copies nothing when the token has expired', () => {
    const req = run({ isAuthenticated: true, accessToken: jwtWithExp(secondsFromNow(-60)) })
    expect(req.headers.authorization).toBeUndefined()
    // an empty session, and never null: `req.session = null` tells cookie-session to unset the
    // session and its getter then answers null, which makes the login middleware throw
    // 'Express session is not available' instead of starting the sign-in this drop exists to cause
    expect(req.session).toEqual({})
    expect(req.session).not.toBeNull()
  })

  it('passes an unparsable token through for downstream bearer verification to reject', () => {
    const req = run({ isAuthenticated: true, accessToken: 'not-a-jwt' })
    expect(req.headers.authorization).toBe('Bearer not-a-jwt')
  })

  it('leaves an existing authorization header alone', () => {
    const req = run({ isAuthenticated: true, accessToken: jwtWithExp(secondsFromNow(60)) }, 'Bearer existing')
    expect(req.headers.authorization).toBe('Bearer existing')
  })

  it('does nothing for an unauthenticated session', () => {
    const req = run({})
    expect(req.headers.authorization).toBeUndefined()
  })
})

const AUTHORITY = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111'
const OTHER_AUTHORITY = 'https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222'

const runWithOverride = async (
  session: Request['session'],
  authorizationUrlRequestOverride?: AuthConfig['authorizationUrlRequestOverride'],
) => {
  const req = { headers: {}, session } as unknown as Request
  const next = vi.fn()
  createCopySessionJwtToBearerHeader({ authorizationUrlRequestOverride })(req, {} as Response, next as NextFunction)
  await vi.waitFor(() => expect(next).toHaveBeenCalledOnce())
  return req
}

const signedInAt = (authority?: string) => ({
  isAuthenticated: true,
  accessToken: jwtWithExp(secondsFromNow(60)),
  ...(authority ? { authority } : {}),
})

describe('createCopySessionJwtToBearerHeader, against an override', () => {
  it('drops a session that signed in at another authority, so the login middleware re-runs', async () => {
    // without this the session passes straight through, the override never runs, and a request
    // asking for another authority is a no-op for anyone already signed in
    const req = await runWithOverride(signedInAt(AUTHORITY), () => ({ authority: OTHER_AUTHORITY }))

    expect(req.headers.authorization).toBeUndefined()
    expect(req.session).toEqual({})
  })

  it('copies the token where the request would sign in at the same authority', async () => {
    const session = signedInAt(AUTHORITY)
    const req = await runWithOverride(session, () => ({ authority: AUTHORITY }))

    expect(req.headers.authorization).toBe(`Bearer ${session.accessToken}`)
  })

  it('awaits an override that answers asynchronously', async () => {
    const req = await runWithOverride(signedInAt(AUTHORITY), () => Promise.resolve({ authority: OTHER_AUTHORITY }))

    expect(req.session).toEqual({})
  })

  it('copies the token where the override names no authority', async () => {
    const session = signedInAt(AUTHORITY)
    const req = await runWithOverride(session, () => ({ prompt: 'select_account' }))

    expect(req.headers.authorization).toBe(`Bearer ${session.accessToken}`)
  })

  it('copies the token for a session written before this release, which carries no authority', async () => {
    const session = signedInAt()
    const req = await runWithOverride(session, () => ({ authority: OTHER_AUTHORITY }))

    // nothing to compare, so nothing to act on. The expiry drop above is unaffected either way
    expect(req.headers.authorization).toBe(`Bearer ${session.accessToken}`)
  })

  it('copies the token when the override throws, which is what it did before this check existed', async () => {
    const session = signedInAt(AUTHORITY)
    const req = await runWithOverride(session, () => {
      throw new Error('the override is broken')
    })

    expect(req.headers.authorization).toBe(`Bearer ${session.accessToken}`)
  })

  it('still drops an expired token before it ever asks the override', async () => {
    const authorizationUrlRequestOverride = vi.fn(() => ({ authority: AUTHORITY }))
    const req = await runWithOverride(
      { isAuthenticated: true, accessToken: jwtWithExp(secondsFromNow(-60)), authority: AUTHORITY },
      authorizationUrlRequestOverride,
    )

    expect(req.session).toEqual({})
    expect(authorizationUrlRequestOverride).not.toHaveBeenCalled()
  })
})

describe('copySessionJwtToBearerHeader', () => {
  it('is the same middleware with no override, so it only ever drops an expired token', async () => {
    const session = signedInAt(AUTHORITY)
    const req = { headers: {}, session } as unknown as Request
    const next = vi.fn()

    copySessionJwtToBearerHeader(req, {} as Response, next as NextFunction)

    expect(req.headers.authorization).toBe(`Bearer ${session.accessToken}`)
  })
})
