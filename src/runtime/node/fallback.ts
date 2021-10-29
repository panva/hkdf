import { createHmac } from 'crypto'

export default (
  digest: 'sha1' | 'sha256' | 'sha384' | 'sha512',
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  keylen: number,
) => {
  const hashlen = parseInt(digest.substr(3), 10) >> 3 || 20
  const prk = createHmac(digest, salt.byteLength ? salt : new Uint8Array(hashlen))
    .update(ikm)
    .digest()

  // T(0) = empty
  // T(1) = HMAC(PRK, T(0) | info | 0x01)
  // T(2) = HMAC(PRK, T(1) | info | 0x02)
  // T(3) = HMAC(PRK, T(2) | info | 0x03)
  // ...
  // T(N) = HMAC(PRK, T(N-1) | info | N)

  const N = Math.ceil(keylen / hashlen)

  // Single T buffer to accomodate T = T(1) | T(2) | T(3) | ... | T(N)
  // with a little extra for info | N during T(N)
  const T = new Uint8Array(hashlen * N + info.byteLength + 1)
  let prev = 0
  let start = 0
  for (let c = 1; c <= N; c++) {
    T.set(info, start)
    T[start + info.byteLength] = c

    T.set(
      createHmac(digest, prk)
        .update(T.subarray(prev, start + info.byteLength + 1))
        .digest(),
      start,
    )

    prev = start
    start += hashlen
  }

  // OKM, releasing T
  return T.slice(0, keylen)
}
