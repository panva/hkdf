import hkdf from '../dist/web/index.js'

const headers = { 'content-type': 'application/json' }
function respond(status, error) {
  const body = {}
  if (status !== 200) {
    body.error = error.stack
  }
  return new Response(JSON.stringify(body), { headers, status })
}
const success = respond.bind(undefined, 200)
const failure = respond.bind(undefined, 400)
addEventListener('fetch', (event) => {
  event.respondWith(test().then(success, failure))
})

const array = (input) => [
  ...new Uint8Array((input.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))),
]
