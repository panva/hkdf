import { assertEquals } from 'https://deno.land/std@0.110.0/testing/asserts.ts'

import hkdf from '../dist/deno/index.ts'
const vectors: Record<string, [string, string, string, string, number, string, string]> =
  JSON.parse(await Deno.readTextFile('./test/vectors.json'))

const array = (input: string) => [
  ...new Uint8Array((input.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))),
]

for (const vector of Object.entries(vectors)) {
  const [link, [digest, ikm, salt, info, keylen, , okm]] = vector

  Deno.test(link, async () => {
    const result = await hkdf(
      digest,
      Uint8Array.from(array(<string>ikm)),
      Uint8Array.from(array(<string>salt)),
      Uint8Array.from(array(<string>info)),
      keylen,
    )
    assertEquals([...result], array(<string>okm))
  })
}
