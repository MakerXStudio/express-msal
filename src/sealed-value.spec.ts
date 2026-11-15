import { describe, expect, it } from 'vitest'
import { isSealedValue, openValue, sealValue } from './sealed-value'

const SECRET = 'the-cookie-secret'
const OTHER_SECRET = 'another-secret'

describe('sealValue and openValue', () => {
  it('opens what it seals, and the sealed value does not hold the plain value', () => {
    const sealed = sealValue('a value', SECRET)

    expect(sealed).toMatch(/^enc:v1:[A-Za-z0-9_-]+$/)
    expect(sealed).not.toContain('a value')
    expect(openValue(sealed, SECRET)).toBe('a value')
  })

  it('gives a new sealed value each time, because each has its own IV', () => {
    expect(sealValue('a value', SECRET)).not.toBe(sealValue('a value', SECRET))
  })

  it('does not open a value sealed with another secret', () => {
    expect(openValue(sealValue('a value', OTHER_SECRET), SECRET)).toBeUndefined()
  })

  it('does not open a value with a changed byte', () => {
    const sealed = sealValue('a value', SECRET)
    const bytes = Buffer.from(sealed.slice('enc:v1:'.length), 'base64url')
    bytes[bytes.length - 1] ^= 1

    expect(openValue(`enc:v1:${bytes.toString('base64url')}`, SECRET)).toBeUndefined()
  })

  it('does not open a value that is too short to hold an IV and a tag', () => {
    expect(openValue('enc:v1:AAAA', SECRET)).toBeUndefined()
  })

  it('seals with the first secret, and opens with any secret in the list', () => {
    const sealedBefore = sealValue('a value', OTHER_SECRET)
    const sealedAfter = sealValue('a value', [SECRET, OTHER_SECRET])

    expect(openValue(sealedBefore, [SECRET, OTHER_SECRET])).toBe('a value')
    expect(openValue(sealedAfter, SECRET)).toBe('a value')
    expect(openValue(sealedAfter, OTHER_SECRET)).toBeUndefined()
  })

  it('returns undefined for a value with no prefix, or a value that is not a string', () => {
    expect(openValue('eyJhbGciOiJSUzI1NiJ9.e30.signature', SECRET)).toBeUndefined()
    expect(openValue(undefined, SECRET)).toBeUndefined()
    expect(isSealedValue('eyJhbGciOiJSUzI1NiJ9.e30.signature')).toBe(false)
    expect(isSealedValue(sealValue('a value', SECRET))).toBe(true)
  })

  it('throws for an empty secret, or an empty list of secrets', () => {
    expect(() => sealValue('a value', '')).toThrow('sessionSecret')
    expect(() => sealValue('a value', [])).toThrow('sessionSecret')
    expect(() => openValue(sealValue('a value', SECRET), [SECRET, ''])).toThrow('sessionSecret')
  })
})
