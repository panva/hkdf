import derive from './runtime/hkdf.js'

function normalizeDigest(digest: string) {
  switch (digest) {
    case 'sha256':
    case 'sha384':
    case 'sha512':
    case 'sha1':
      return digest
    default:
      throw new TypeError('unsupported "digest" value')
  }
}

function normalizeUint8Array(input: unknown, label: string) {
  if (typeof input === 'string') return new TextEncoder().encode(input)
  if (!(input instanceof Uint8Array))
    throw new TypeError(`"${label}"" must be an instance of Uint8Array or a string`)
  return input
}

function normalizeIkm(input: unknown) {
  const ikm = normalizeUint8Array(input, 'ikm')
  if (!ikm.byteLength) throw new TypeError(`"ikm" must be at least one byte in length`)
  return ikm
}

function normalizeInfo(input: unknown) {
  const info = normalizeUint8Array(input, 'info')
  if (info.byteLength > 1024) {
    throw TypeError('"info" must not contain more than 1024 bytes')
  }
  return info
}

function normalizeKeylen(input: unknown, digest: string) {
  if (typeof input !== 'number' || !Number.isInteger(input) || input < 1) {
    throw new TypeError('"keylen" must be a positive integer')
  }
  const hashlen = parseInt(digest.substr(3), 10) >> 3 || 20
  if (input > 255 * hashlen) {
    throw new TypeError('"keylen" too large')
  }
  return input
}

/**
 * HKDF is a simple key derivation function defined in RFC 5869.
 * The given `ikm`, `salt` and `info` are used with the `digest` to
 * derive a key of `keylen` bytes.
 *
 * @param digest The digest algorithm to use.
 * @param ikm The input keying material. It must be at least one byte in length.
 * @param salt The salt value. Must be provided but can be zero-length.
 * @param info Additional info value. Must be provided but can be zero-length, and cannot be more than 1024 bytes.
 * @param keylen The length in bytes of the key to generate. Must be greater than 0 and no more than 255 times the digest size.
 */
async function hkdf(
  digest: 'sha256' | 'sha384' | 'sha512' | 'sha1' | string,
  ikm: Uint8Array | string,
  salt: Uint8Array | string,
  info: Uint8Array | string,
  keylen: number,
): Promise<Uint8Array> {
  return derive(
    normalizeDigest(digest),
    normalizeIkm(ikm),
    normalizeUint8Array(salt, 'salt'),
    normalizeInfo(info),
    normalizeKeylen(keylen, digest),
  )
}

export { hkdf, hkdf as default }
