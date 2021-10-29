import test from 'ava'
import hkdf from '#dist'

const params = ({
  digest = 'sha256',
  ikm = new Uint8Array([0x00]),
  salt = new Uint8Array(),
  info = new Uint8Array(),
  keylen = 64,
} = {}) => [digest, ikm, salt, info, keylen]

{
  // normalize keylen
  test('invalid keylen', async (t) => {
    for (const keylen of [0, -1, Infinity, -Infinity, NaN]) {
      await t.throwsAsync(() => hkdf(...params({ keylen })), {
        message: '"keylen" must be a positive integer',
      })
    }
  })

  test('minimum keylen', async (t) => {
    return t.notThrowsAsync(() => hkdf(...params({ keylen: 1 })))
  })

  test('maximum keylen for sha1', async (t) => {
    const keylen = 20 * 255
    await t.throwsAsync(() => hkdf(...params({ keylen: keylen + 1, digest: 'sha1' })), {
      message: '"keylen" too large',
    })
    return t.notThrowsAsync(() => hkdf(...params({ keylen, digest: 'sha1' })))
  })

  test('maximum keylen for sha256', async (t) => {
    const keylen = 32 * 255
    await t.throwsAsync(() => hkdf(...params({ keylen: keylen + 1, digest: 'sha256' })), {
      message: '"keylen" too large',
    })
    return t.notThrowsAsync(() => hkdf(...params({ keylen, digest: 'sha256' })))
  })

  test('maximum keylen for sha384', async (t) => {
    const keylen = 48 * 255
    await t.throwsAsync(() => hkdf(...params({ keylen: keylen + 1, digest: 'sha384' })), {
      message: '"keylen" too large',
    })
    return t.notThrowsAsync(() => hkdf(...params({ keylen, digest: 'sha384' })))
  })

  test('maximum keylen for sha512', async (t) => {
    const keylen = 64 * 255
    await t.throwsAsync(() => hkdf(...params({ keylen: keylen + 1, digest: 'sha512' })), {
      message: '"keylen" too large',
    })
    return t.notThrowsAsync(() => hkdf(...params({ keylen, digest: 'sha512' })))
  })
}

{
  // normalize info
  test('info can be zero-length', async (t) => {
    await t.notThrowsAsync(() => hkdf(...params({ info: '' })))
    await t.notThrowsAsync(() => hkdf(...params({ info: new Uint8Array() })))
  })

  test('info can be up to 2048 bytes', async (t) => {
    await t.notThrowsAsync(() => hkdf(...params({ info: 'a'.repeat(1024) })))
    await t.notThrowsAsync(() => hkdf(...params({ info: new Uint8Array(1024) })))
    for (const info of [new Uint8Array(1025), 'a'.repeat(1025)]) {
      await t.throwsAsync(() => hkdf(...params({ info })), {
        message: '"info" must not contain more than 1024 bytes',
      })
    }
  })

  test('info must be string or Uint8Array', async (t) => {
    for (const info of [[], Object, Boolean, {}, null, NaN, 0, 1, -1, Infinity, true, false]) {
      await t.throwsAsync(() => hkdf(...params({ info })), {
        message: '"info"" must be an instance of Uint8Array or a string',
      })
    }
  })
}

{
  // normalize salt
  test('salt can be zero-length', async (t) => {
    await t.notThrowsAsync(() => hkdf(...params({ salt: '' })))
    await t.notThrowsAsync(() => hkdf(...params({ salt: new Uint8Array() })))
  })

  test('salt is not limited to 2048 bytes', async (t) => {
    await t.notThrowsAsync(() => hkdf(...params({ salt: 'a'.repeat(1024) })))
    await t.notThrowsAsync(() => hkdf(...params({ salt: new Uint8Array(1024) })))
    for (const salt of [new Uint8Array(1025), 'a'.repeat(1025)]) {
      await t.notThrowsAsync(() => hkdf(...params({ salt })))
    }
  })

  test('salt must be string or Uint8Array', async (t) => {
    for (const salt of [[], Object, Boolean, {}, null, NaN, 0, 1, -1, Infinity, true, false]) {
      await t.throwsAsync(() => hkdf(...params({ salt })), {
        message: '"salt"" must be an instance of Uint8Array or a string',
      })
    }
  })
}

{
  // normalize ikm
  test('ikm must not be zero-length', async (t) => {
    for (const ikm of ['', new Uint8Array()]) {
      await t.throwsAsync(() => hkdf(...params({ ikm })), {
        message: '"ikm" must be at least one byte in length',
      })
    }
  })

  test('ikm is not limited to 2048 bytes', async (t) => {
    await t.notThrowsAsync(() => hkdf(...params({ ikm: 'a'.repeat(1024) })))
    await t.notThrowsAsync(() => hkdf(...params({ ikm: new Uint8Array(1024) })))
    for (const ikm of [new Uint8Array(1025), 'a'.repeat(1025)]) {
      await t.notThrowsAsync(() => hkdf(...params({ ikm })))
    }
  })

  test('ikm must be string or Uint8Array', async (t) => {
    for (const ikm of [[], Object, Boolean, {}, null, NaN, 0, 1, -1, Infinity, true, false]) {
      await t.throwsAsync(() => hkdf(...params({ ikm })), {
        message: '"ikm"" must be an instance of Uint8Array or a string',
      })
    }
  })
}

{
  // normalize digest
  test('digest must be a recognized one', async (t) => {
    for (const digest of [
      [],
      Object,
      Boolean,
      {},
      null,
      NaN,
      0,
      1,
      -1,
      Infinity,
      true,
      false,
      'sha224',
      'foo',
    ]) {
      await t.throwsAsync(() => hkdf(...params({ digest })), {
        message: 'unsupported "digest" value',
      })
    }
  })
}
