# Upsy OAuth Bridge

Cloudflare Worker that completes the Upsy OAuth authorization-code flow with PKCE, stores OAuth tokens in a Durable Object, refreshes tokens, and proxies MCP requests to https://upsy.ai/connect.

This fork adds a fail-closed owner password. Nothing that can start or finish OAuth, show token status, or reach Upsy works until the owner has set a password.

## Deploy
1. `npx wrangler deploy` (or connect the repo with Cloudflare Workers Builds).
2. Add a secret named `SETUP_CODE` (at least 24 random characters): `npx wrangler secret put SETUP_CODE`, or Worker > Settings > Variables and Secrets > Add > Secret.
3. Open `/setup`, enter the setup code, then open the one-time link it shows (valid once, for 10 minutes) and choose the owner password (at least 12 characters).

The password is stored only as a salted HMAC-SHA256 hash in the Durable Object. It is never written to the repo, the URL or the logs.

## Connect Upsy
Sign in at `/`, press Connect Upsy, and authorize Upsy. The callback only completes in the same signed-in browser that started it.

## Use from an MCP client
URL: `https://<your-worker>/mcp`
Header: `Authorization: Bearer <owner password>` (or `X-Bridge-Key: <owner password>`).
The bridge strips that header and sends its own Upsy access token upstream. Clients that cannot send a custom header cannot use the bridge.

## Endpoints
- GET /health: public liveness only (`locked` true until a password exists). Token status shows only to a signed-in session.
- GET/POST /setup, /setup/password: one-time owner setup, gated by the `SETUP_CODE` secret.
- GET / and GET/POST /login, POST /logout: owner sign-in (12-hour HttpOnly, Secure, SameSite=Lax session cookie).
- POST /auth/start: starts OAuth (signed-in session and same-origin form post required).
- GET /oauth/callback: OAuth callback (signed-in session, single-use state bound to that session).
- POST, DELETE /mcp: proxies MCP to Upsy (bearer password required).

## Security notes
- Fail closed: with no password set, /mcp returns 503 and the OAuth routes show a locked page. Without `SETUP_CODE`, setup is off too.
- Failed setup-code, sign-in and /mcp key attempts are limited to 10 per client IP per 15 minutes.
- Password reset: change the `SETUP_CODE` secret, then run setup again. A setup code can only be used once.
- Anyone who learns the password can use every Upsy connection the bridge was authorized for. Use a long, unique password and keep the Worker URL private.
- The stored Upsy tokens sit in the Durable Object in plain form, readable by anyone with access to the Cloudflare account.
