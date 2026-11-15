import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
import { deflateRawSync, inflateRawSync } from 'node:zlib'

/** One secret, or a list whose first secret seals and each of which opens. */
export type SessionSecret = string | string[]

const PREFIX = 'enc:v1:'
const KEY_INFO = 'express-msal session v1'
const IV_LENGTH = 12
const TAG_LENGTH = 16

// HKDF gives a 32-byte key from a secret of any length, so an app can pass the secret that signs
// its cookie
const deriveKey = (secret: string) => Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), KEY_INFO, 32))

/** Returns the secrets as a list, and throws when the list or a secret in it is empty. */
export const toSecretList = (sessionSecret: SessionSecret): string[] => {
  const secrets = Array.isArray(sessionSecret) ? sessionSecret : [sessionSecret]
  if (secrets.length === 0 || secrets.some((secret) => typeof secret !== 'string' || secret.length === 0)) {
    throw new Error('sessionSecret must be a non-empty string, or a non-empty list of non-empty strings')
  }
  return secrets
}

/** Returns true when the value has the prefix of a sealed value. It does not check that the value opens. */
export const isSealedValue = (value: unknown): value is string => typeof value === 'string' && value.startsWith(PREFIX)

/**
 * Encrypts a value with AES-256-GCM, under a key derived from the first secret.
 *
 * The value is compressed first. cookie-session base64-encodes the session again, so a sealed JWT
 * without compression makes a cookie about 1.8 times the size of the token.
 */
export const sealValue = (value: string, sessionSecret: SessionSecret): string => {
  const [secret] = toSecretList(sessionSecret)
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', deriveKey(secret), iv)
  const cipherText = Buffer.concat([cipher.update(deflateRawSync(Buffer.from(value, 'utf8'))), cipher.final()])
  return `${PREFIX}${Buffer.concat([iv, cipher.getAuthTag(), cipherText]).toString('base64url')}`
}

/**
 * Decrypts a value that {@link sealValue} returned, with each secret in turn. Returns `undefined`
 * when the value is not a sealed value, or when no secret opens it.
 */
export const openValue = (value: unknown, sessionSecret: SessionSecret): string | undefined => {
  if (!isSealedValue(value)) return undefined
  const sealed = Buffer.from(value.slice(PREFIX.length), 'base64url')
  if (sealed.length < IV_LENGTH + TAG_LENGTH) return undefined

  const iv = sealed.subarray(0, IV_LENGTH)
  const tag = sealed.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH)
  const cipherText = sealed.subarray(IV_LENGTH + TAG_LENGTH)

  for (const secret of toSecretList(sessionSecret)) {
    try {
      const decipher = createDecipheriv('aes-256-gcm', deriveKey(secret), iv, { authTagLength: TAG_LENGTH })
      decipher.setAuthTag(tag)
      return inflateRawSync(Buffer.concat([decipher.update(cipherText), decipher.final()])).toString('utf8')
    } catch {
      // the wrong key, or a changed value: try the next secret
    }
  }
  return undefined
}
