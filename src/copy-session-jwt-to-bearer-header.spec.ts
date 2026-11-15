import { NextFunction, Request, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { AuthConfig, copySessionJwtToBearerHeader, createCopySessionJwtToBearerHeader, sealValue } from './index'

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
    const session = { isAuthenticated: true, accessToken: jwtWithExp(secondsFromNow(-60)) }
    const req = run(session)

    expect(req.headers.authorization).toBeUndefined()
    // the same object, emptied. Not null, whose getter answers null and makes the login middleware
    // throw 'Express session is not available' instead of starting the sign-in this drop exists to
    // cause; and not a replacement, which cookie-session takes for new-and-unpopulated and so
    // neither saves nor removes, leaving the stale cookie to come back on the next request
    expect(req.session).toBe(session)
    expect(req.session).toEqual({})
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
    const session = signedInAt(AUTHORITY)
    const req = await runWithOverride(session, () => ({ authority: OTHER_AUTHORITY }))

    expect(req.headers.authorization).toBeUndefined()
    // emptied in place, for the reason the expiry drop above gives
    expect(req.session).toBe(session)
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

  it('empties an expired session in place even when an override is configured', async () => {
    const session = signedInAt(AUTHORITY)
    session.accessToken = jwtWithExp(secondsFromNow(-60))
    const req = await runWithOverride(session, () => ({ authority: AUTHORITY }))

    expect(req.session).toBe(session)
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

const SECRET = 'the-cookie-secret'

const createLogger = () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn(), verbose: vi.fn(), debug: vi.fn() })

const runWithSecret = async (
  session: Request['session'],
  options: Pick<AuthConfig, 'sessionSecret' | 'authorizationUrlRequestOverride'> = { sessionSecret: SECRET },
  logger = createLogger(),
) => {
  const req = { headers: {}, session } as unknown as Request
  const next = vi.fn()
  createCopySessionJwtToBearerHeader({ ...options, logger })(req, {} as Response, next as NextFunction)
  await vi.waitFor(() => expect(next).toHaveBeenCalledOnce())
  return req
}

describe('createCopySessionJwtToBearerHeader, with sessionSecret', () => {
  it('copies the plain token of a sealed session, and does not change the session', async () => {
    const accessToken = jwtWithExp(secondsFromNow(60))
    const session = { isAuthenticated: true, accessToken: sealValue(accessToken, SECRET) }
    const before = { ...session }
    const req = await runWithSecret(session)

    expect(req.headers.authorization).toBe(`Bearer ${accessToken}`)
    // a changed session makes cookie-session send a Set-Cookie on every request
    expect(req.session).toEqual(before)
  })

  it('copies a token that an earlier secret in the list sealed', async () => {
    const accessToken = jwtWithExp(secondsFromNow(60))
    const req = await runWithSecret(
      { isAuthenticated: true, accessToken: sealValue(accessToken, 'the-old-secret') },
      { sessionSecret: [SECRET, 'the-old-secret'] },
    )

    expect(req.headers.authorization).toBe(`Bearer ${accessToken}`)
  })

  it('drops the session when the sealed token has expired', async () => {
    const session = { isAuthenticated: true, accessToken: sealValue(jwtWithExp(secondsFromNow(-60)), SECRET) }
    const req = await runWithSecret(session)

    expect(req.headers.authorization).toBeUndefined()
    expect(req.session).toBe(session)
    expect(req.session).toEqual({})
  })

  it('drops a session with a plain token, which a cookie from before the upgrade holds', async () => {
    const session = { isAuthenticated: true, accessToken: jwtWithExp(secondsFromNow(60)) }
    const req = await runWithSecret(session)

    expect(req.headers.authorization).toBeUndefined()
    expect(req.session).toBe(session)
    expect(req.session).toEqual({})
  })

  it('drops a session whose token does not open, and logs at verbose', async () => {
    const logger = createLogger()
    const session = { isAuthenticated: true, accessToken: sealValue(jwtWithExp(secondsFromNow(60)), 'another-secret') }
    const req = await runWithSecret(session, { sessionSecret: SECRET }, logger)

    expect(req.headers.authorization).toBeUndefined()
    expect(req.session).toEqual({})
    expect(logger.verbose).toHaveBeenCalledWith(expect.stringContaining('not sealed with a current sessionSecret'))
  })

  it('compares the authority after it opens the token', async () => {
    const session = {
      isAuthenticated: true,
      accessToken: sealValue(jwtWithExp(secondsFromNow(60)), SECRET),
      authority: AUTHORITY,
    }
    const req = await runWithSecret(session, {
      sessionSecret: SECRET,
      authorizationUrlRequestOverride: () => ({ authority: OTHER_AUTHORITY }),
    })

    expect(req.headers.authorization).toBeUndefined()
    expect(req.session).toEqual({})
  })

  it('throws when it is created with an empty sessionSecret', () => {
    expect(() => createCopySessionJwtToBearerHeader({ sessionSecret: '' })).toThrow('sessionSecret')
  })
})

describe('createCopySessionJwtToBearerHeader, without sessionSecret', () => {
  it('drops a sealed session, and logs a warning once', async () => {
    const logger = createLogger()
    const middleware = createCopySessionJwtToBearerHeader({ logger })
    const sealedSession = () => ({ isAuthenticated: true, accessToken: sealValue(jwtWithExp(secondsFromNow(60)), SECRET) })

    for (let i = 0; i < 2; i++) {
      const req = { headers: {}, session: sealedSession() } as unknown as Request
      middleware(req, {} as Response, vi.fn() as NextFunction)
      expect(req.headers.authorization).toBeUndefined()
      expect(req.session).toEqual({})
    }
    expect(logger.warn).toHaveBeenCalledOnce()
  })
})
