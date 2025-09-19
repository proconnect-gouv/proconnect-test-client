# ProConnect Test Client

This is a minimal, nodeJS-based ProConnect client, to be used for end-to-end testing.

It uses the https://github.com/panva/node-openid-client Library for the actual OIDC Logic.

This tool can be used to test the traditional Authorization Code Flow.

It also uses the `select_organization` & `update_userinfo` ProConnect prompts (available only on ProConnect Identité).

This tool is fully configured using environment variables.

## Run it with Docker

Pull the image:

```
docker pull ghcr.io/proconnect-gouv/proconnect-test-client
```

Run the container:

```
docker run --rm \
-p 3000:3000 \
-e PORT=3000 \
ghcr.io/proconnect-gouv/proconnect-test-client
```

## Run it with Docker Compose

In `docker-compose.yml`:

```yaml
version: "3.5"

services:
  proconnect-test-client:
    image: proconnect-gouv/proconnect-test-client
    ports:
      - 3000:3000
    environment:
      PORT: 3000
```

Run the container:

```
docker-compose up
```

## Run it with Node.js v16 or higher

Install the dependencies:

```
npm i
```

Run the server:

```
npm start
```

## Configuration

Available env variables for ProConnect Identité are listed [here](.env).

Available env variables for ProConnect Fédération are listed [here](federation.env).

You can use the app-sandbox.moncomptepro.beta.gouv.fr oidc provider with the following client configuration:

```yaml
client_id: client_id
client_secret: client_secret
login_callbacks: ["http://localhost:3000/login-callback"]
logout_callbacks: ["http://localhost:3000/"]
authorized_scopes: openid email profile organization
```

More clients are available at: https://github.com/proconnect-gouv/moncomptepro/blob/main/scripts/fixtures.sql

## Run Cypress test

```
cd e2e
npm i
npm test
```
