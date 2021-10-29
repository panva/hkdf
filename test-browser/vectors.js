import hkdf from '../dist/web/index.js'
import vectors from '../test/vectors.json'

const array = (input) => [
  ...new Uint8Array((input.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))),
]

for (const vector of Object.entries(vectors)) {
  const [link, [digest, ikm, salt, info, keylen, , okm]] = vector

  QUnit.test(link, async (t) => {
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
