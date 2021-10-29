import * as crypto from 'crypto'

import fallback from './fallback.js'

let hkdf: (
  digest: string,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  keylen: number,
) => Promise<Uint8Array>

if (typeof crypto.hkdf === 'function' && !process.versions.electron) {
  hkdf = async (...args) =>
    new Promise((resolve, reject) => {
      crypto.hkdf(...args, (err, arrayBuffer) => {
        if (err) reject(err)
        else resolve(new Uint8Array(arrayBuffer))
      })
    })
}

export default async (
  digest: 'sha1' | 'sha256' | 'sha384' | 'sha512',
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  keylen: number,
): Promise<Uint8Array> => (hkdf || fallback)(digest, ikm, salt, info, keylen)
