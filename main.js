const {
  POSTMARK_SERVER_API_KEY,
  POSTMARK_FROM_ADDRESS,
  KEYGEN_ACCOUNT_ID,
  KEYGEN_VERIFY_KEY,
  SCHEME = 'http',
  HOST = 'localhost:8080',
  PORT = 8080
} = process.env

const { html } = require('common-tags')
const postmark = require('postmark')
const crypto = require('crypto')
const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const ejs = require('ejs')

const client = new postmark.Client(POSTMARK_SERVER_API_KEY)
const app = express()

function verifyWebhookSignature(req) {
  try {
    const header = req.headers['keygen-signature']
    if (header == null) {
      console.warn(`Signature is missing`)

      return false
    }

    // Parse the signature header into an object
    const params = header.split(/,\s{0,1}/g)
      .map(keyvalue => keyvalue.match(/(?<key>[^=]+)="(?<value>[^"]+)"/i))
      .map(matches => matches.groups)
      .reduce(
        (obj, { key, value }) => (obj[key] = value, obj),
        {}
      )

    // Assert the signature algorithm is what we expect
    const { algorithm, signature } = params
    if (algorithm !== 'ed25519') {
      console.warn(`Algorithm did not match: ${algorithm}`)

      return false
    }

    // Create a SHA-256 digest of the plaintext respose body (before it's parsed)
    const hash = crypto.createHash('sha256').update(req.plaintext)
    const digest = `sha-256=${hash.digest('base64')}`
    if (digest !== req.headers['digest']) {
      console.warn(`Digest did not match: ${digest}`)

      return false
    }

    // Reconstruct the webhook signing data
    const host = req.headers['host']
    const date = req.headers['date']
    const data = [
      `(request-target): ${req.method.toLowerCase()} ${req.path}`,
      `host: ${host}`,
      `date: ${date}`,
      `digest: ${digest}`,
    ].join('\n')

    // Decode and plug in our DER-encoded verify key
    const verifyKey = crypto.createPublicKey({
      key: Buffer.from(KEYGEN_VERIFY_KEY, 'base64'),
      format: 'der',
      type: 'spki',
    })

    // Verify the signature
    const signatureBytes = Buffer.from(signature, 'base64')
    const dataBytes = Buffer.from(data)

    return crypto.verify(null, dataBytes, verifyKey, signatureBytes)
  } catch (e) {
    console.error(`Failed to verify webhook: request=${req.headers['x-request-id'] || 'N/A'}`, e)

    return false
  }
}

// NOTE(ezekg) Hack to store a reference to the plaintext request body
app.use(bodyParser.json({
  verify: (req, res, buf) => req.plaintext = buf != null ? buf.toString() : null,
  type: ['application/vnd.api+json', 'application/json'],
}))

app.use(morgan('combined'))

// The webhook endpoint that listens for password reset requests from Keygen
app.post('/webhooks', async (req, res) => {
  const { data } = req.body

  // Verify the authenticity of the webhook i.e. that it came from Keygen
  if (!verifyWebhookSignature(req)) {
    console.error(`Signature did not match: webhook_event_id=${data?.id}`)

    return res.sendStatus(400)
  }

  switch (data.attributes.event) {
    case 'user.password-reset': {
      const { meta, data: user } = JSON.parse(data.attributes.payload)

      // This points to the route below, which will render a form that submits
      // the password reset fulfillment to Keygen's API.
      const link = `${SCHEME}://${HOST}/reset/${user.id}/${meta.passwordResetToken}`

      try {
        await client.sendEmail({
          From: POSTMARK_FROM_ADDRESS,
          To: user.attributes.email,
          Subject: 'Complete your password reset',
          HtmlBody: html`
            <p>Please reset your password by following this link within 24 hours:</p>
            <a href='${link}'>${link}</a>
          `
        })
      } catch (e) {
        console.error(`Failed to send password reset: user=${user.id || 'N/A'} link=${link || 'N/A'}`, e)

        return res.sendStatus(400)
      }

      break
    }
  }

  res.sendStatus(204)
})

// Our password reset fulfillment route. This accepts a :userId and a :passwordResetToken.
// It renders an HTML page which sends an API request to Keygen to fulfill the user's
// password reset request. This could also be a static website -- no server is really
// needed, it just makes this example easier.
app.get('/reset/:userId/:passwordResetToken', async (req, res) => {
  const { userId, passwordResetToken } = req.params
  const content = await ejs.renderFile('views/fulfill-password-reset.html.ejs', {
    accountId: KEYGEN_ACCOUNT_ID,
    userId,
    passwordResetToken,
  })

  res.contentType('text/html')
     .send(content)
})

// Our password reset route. It renders an HTML page that accepts a user's email
// address. Once submitted, we send an API request to Keygen that triggers a
// password reset webhook, which we handle in our /webhooks route.
app.get('/reset', async (req, res) => {
  const content = await ejs.renderFile('views/request-password-reset.html.ejs', {
    accountId: KEYGEN_ACCOUNT_ID,
  })

  res.contentType('text/html')
     .send(content)
})

app.get('/', async (req, res) =>
  res.redirect('/reset')
)

const server = app.listen(PORT, 'localhost', () => {
  const { address, port } = server.address()

  console.log(`Listening at http://${address}:${port}`)
})
