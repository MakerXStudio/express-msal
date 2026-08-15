import { NextFunction, Request, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { copySessionJwtToBearerHeader } from './index'

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
    expect(req.session).toBeNull()
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
