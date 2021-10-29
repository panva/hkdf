import { randomUUID } from 'node:crypto'
import { execSync } from 'node:child_process'
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs'
import { setTimeout } from 'node:timers/promises'

import test from 'ava'
import throttle from 'p-throttle'
import Got from 'got'

const vectors = JSON.parse(readFileSync('./test/vectors.json'))

const got = Got.extend({
  http2: true,
  throwHttpErrors: false,
})
const { CF_ACCOUNT_ID, CF_API_TOKEN } = process.env

const baseUrl = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts`
const authorization = `Bearer ${CF_API_TOKEN}`
const TEMPLATE = readFileSync(`./test-cloudflare-workers/template.js`)

const request = throttle({ limit: 10, interval: 1000 })(async (...args) => {
  return got(...args)
})

test.before(async () => {
  const {
    body: { result },
  } = await request({
    responseType: 'json',
    url: baseUrl,
    method: 'GET',
    headers: { authorization },
  })
  for (const { id } of result) {
    request({
      url: `${baseUrl}/${id}`,
      method: 'DELETE',
      headers: { authorization },
    })
  }
})

test.beforeEach((t) => {
  t.context.uuid = randomUUID()
  t.context.file = `./test-cloudflare-workers/.${t.context.uuid}.js`
})

test.afterEach.always(async (t) => {
  let statusCode
  do {
    ;({ statusCode } = await request({
      url: `${baseUrl}/${t.context.uuid}`,
      method: 'DELETE',
      headers: { authorization },
    }))
    await setTimeout(1000)
  } while (statusCode !== 200)
})

const macro = async (t, vector, testScript) => {
  writeFileSync(
    t.context.file,
    `${TEMPLATE}
const data = ${JSON.stringify(vector)}
const test = ${testScript.toString()}
`,
  )

  execSync(`deno bundle ${t.context.file} ${t.context.file}`, { stdio: 'ignore' })

  let statusCode
  do {
    ;({ statusCode } = await request({
      url: `${baseUrl}/${t.context.uuid}`,
      method: 'PUT',
      headers: { authorization, 'content-type': 'application/javascript' },
      body: readFileSync(t.context.file),
    }))
    t.log(`PUT ${statusCode}`)
    await setTimeout(1000)
  } while (statusCode !== 200)
  unlinkSync(t.context.file)

  do {
    ;({ statusCode } = await request({
      url: `${baseUrl}/${t.context.uuid}/subdomain`,
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ enabled: true }),
    }))
    t.log(`POST ${statusCode}`)
    await setTimeout(1000)
  } while (statusCode !== 200)

  statusCode = 0
  let body
  let i = 0
  do {
    ;({ statusCode, body } = await request({
      method: 'GET',
      url: `https://${t.context.uuid}.panva.workers.dev`,
      responseType: 'json',
    }))
    i++
    await setTimeout(1000)
  } while (statusCode !== 200 && statusCode !== 400)

  t.log(`${i}s until execution`)
  if (statusCode === 200) {
    t.pass()
  } else {
    t.log(body)
    t.fail()
  }
}

const array = (input) => [...Buffer.from(input, 'hex')]

for (const vector of Object.entries(vectors)) {
  const [link, data] = vector
  test(link, macro, data, async () => {
    const [digest, ikm, salt, info, keylen, , okm] = data
    const result = await hkdf(
      digest,
      Uint8Array.from(array(ikm)),
      Uint8Array.from(array(salt)),
      Uint8Array.from(array(info)),
      keylen,
    )

    if (!array(okm).every((val, i) => [...result][i] === val)) {
      throw new Error('not equal')
    }
  })
}
