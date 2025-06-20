> [!IMPORTANT]
> This project is now archived. The functionality provided here is no longer necessary, as the Web Cryptography API is now widely supported across all major and modern JavaScript runtimes and you may just use the following
> ```ts
> let ikm!: Uint8Array
> let salt!: Uint8Array
> let info!: Uint8Array
> let keyLen!: number
>
> const derivedKey = new Uint8Array(
>   await globalThis.crypto.subtle.deriveBits(
>     {
>       name: 'HKDF',
>       hash: 'SHA-256',
>       salt,
>       info,
>     },
>     await globalThis.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']),
>     keylen << 3,
>   ),
> )
> ```

# hkdf

> HKDF with no dependencies using runtime's native crypto

HKDF is a simple key derivation function defined in [RFC 5869][].

## Documentation

▸ **hkdf**(`digest`, `ikm`, `salt`, `info`, `keylen`): `Promise`<`Uint8Array`\>

The given `ikm`, `salt` and `info` are used with the `digest` to derive a key of `keylen` bytes.

### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `digest` | ``"sha256"`` \| ``"sha384"`` \| ``"sha512"`` \| ``"sha1"`` | The digest algorithm to use. |
| `ikm` | `Uint8Array` \| `string` | The input keying material. It must be at least one byte in length. |
| `salt` | `Uint8Array` \| `string` | The salt value. Must be provided but can be zero-length. |
| `info` | `Uint8Array` \| `string` | Additional info value. Must be provided but can be zero-length, and cannot be more than 1024 bytes. |
| `keylen` | `number` | The length in bytes of the key to generate. Must be greater than 0 and no more than 255 times the digest size. |

### Returns

`Promise`<`Uint8Array`\>

### Example

**`example`** ESM import
```js
import hkdf from '@panva/hkdf'
```

**`example`** CJS import
```js
const { hkdf } = require('@panva/hkdf')
```

**`example`** Deno import
```js
import hkdf from 'https://deno.land/x/hkdf/index.ts'
```

**`example`** Usage
```js
const derivedKey = await hkdf(
  'sha256',
  'key',
  'salt',
  'info',
  64
)
```

## Supported Runtimes

The supported JavaScript runtimes include ones that

- are reasonably up to date ECMAScript
- support the utilized Web API globals and standard built-in objects
- These are
  - _(This is not an exhaustive list)_
  - Browsers
  - Cloudflare Workers
  - Deno
  - Electron
  - Netlify Edge Functions
  - Next.js Middlewares
  - Node.js
  - Vercel Edge Functions

[RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869.html
