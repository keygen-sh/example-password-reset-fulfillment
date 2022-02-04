# Example Password Reset Fulfillment

This is a toy app to act as an example of how to fulfill password reset requests yourself,
using your own email provider and password reset form. **This example app is very basic
and is *not* production ready.**

Not only will this provide better visibility into potential deliverability issues, but
this also lets you brand emails to better match your software (instead of using Keygen's
default branding).

Handling password reset logic yourself consists of 2 things:

1. Creating a small webhook server that listens for the `user.password-reset` webhook
   event, and then sends the included password reset token to the user's email.
2. Creating a small HTML web page that accepts the password reset token to fulfill
   the password reset request using our API.

This example uses [Postmark](https://postmark.com) to send emails, but you're free to
use another provider.

## Running the example

First up, configure a couple application variables. You can find these under your
account settings. **You *must* configure these.**

```bash
# Your Postmark API key for sending email.
POSTMARK_SERVER_API_KEY="xxx"

# The address you're sending mail from.
POSTMARK_FROM_ADDRESS="noreply@acme.example"

# Your Keygen account's DER encoded Ed25519 verify key, used
# for verifying webhooks came from Keygen.
KEYGEN_VERIFY_KEY="MCowBQYDK2VwAyEA6GAeSLaTg7pSAkX9B5cemD0G0ixCV8/YIwRgFHnO54g="

# Your Keygen account ID.
KEYGEN_ACCOUNT_ID="1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"

# The scheme for your server i.e. https.
SCHEME='https'

# The hostname of the server i.e. your domain.
HOST='acme.example'

# The port to run the server on.
PORT=3000
```

Next, install dependencies with [`yarn`](https://yarnpkg.comg):

```bash
yarn
```

Then start the app:

```bash
yarn start
```

Lastly, open the app:

```bash
open http://localhost:8080
```

## Testing the example

#### Set up an Ngrok tunnel

Using [`ngrok`](https://ngrok.com), create a secure tunnel to your local server.
You can download `ngrok` [here](https://ngrok.com/download).

```bash
ngrok http 8080
```

**Please ensure [your *local server* is running](#running-the-example).**

#### Add your webhook endpoint

Using the generated `ngrok` HTTPS URL above, create [a new webhook endpoint](https://app.keygen.sh/webhook-endpoints).
Subscribe your webhook endpoint to the `user.password-reset` event.

```
https://YOUR_NGROK_TUNNEL_ID.ngrok.io/webhooks
```

**Note the *`/webhooks`* path.**

#### Request a password reset

Visit the root of your local server and fill out the password reset request form.

```
open http://localhost:8080/reset
```

Alternatively, you can use `curl` to request a password reset. Be sure to include
`deliver: false` so that Keygen doesn't send an email to the user as well.

```bash
curl -X POST https://api.keygen.sh/v1/accounts/YOUR_KEYGEN_ACCOUNT_ID/passwords \
  -d '{
        "meta": {
          "email": "foo@bar.example",
          "deliver": false
        }
      }'
```

This will trigger a `user.password-reset` event to be sent to your webhook endpoint.
**We *will not* send an email to the user, so deliverability is on you.**

You can view your account's webhook event logs [here](https://app.keygen.sh/webhook-events).

#### Test the new credentials

After fulfilling the password reset request, you can test the user's new credentials
by generating [a user token](https://keygen.sh/docs/api/authentication/#user-tokens).

```bash
curl -X POST https://api.keygen.sh/v1/accounts/YOUR_KEYGEN_ACCOUNT_ID/tokens \
  -u foo@bar.example:YOUR_NEW_PASSWORD
```

## Questions?

Reach out at support@keygen.sh if you have any questions or concerns!
