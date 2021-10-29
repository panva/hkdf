import * as fs from 'fs'

import test from 'ava'
import hkdf from '#dist'

const vectors = JSON.parse(fs.readFileSync('./test/vectors.json'))

const array = (input) => [...Buffer.from(input, 'hex')]

for (const vector of Object.entries(vectors)) {
  const [link, [digest, ikm, salt, info, keylen, , okm]] = vector

  test(link, async (t) => {
    const result = await hkdf(
      digest,
      Uint8Array.from(array(ikm)),
      Uint8Array.from(array(salt)),
      Uint8Array.from(array(info)),
      keylen,
    )
    t.deepEqual([...result], array(okm))
  })
}
