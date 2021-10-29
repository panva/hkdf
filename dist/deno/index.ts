import derive from './runtime/hkdf.ts'

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

function normalizeLength(input: unknown) {
  if (typeof input !== 'number' || !Number.isInteger(input) || input < 1) {
    throw new TypeError('"keylen" must be a positive integer')
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
 * @param keylen The length in bytes of the key to generate. Must be greater than 0.
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
    normalizeLength(keylen),
  )
}

export { hkdf, hkdf as default }
