The two Go binaries we built — that's it:

- **vpnoauth-server** — HTTPS server that sits in front of WireGuard. Handles the Google OAuth2 flow, validates the user's email domain, issues a one-time token, and calls `wg set` to add the authenticated user as a peer with a TTL. Background goroutine removes expired peers. Also serves `/web/connect` — a browser-based flow that completes OAuth and renders a QR code scannable by the WireGuard iOS/Android app (keypair generated server-side).

- **vpnoauth-client** — CLI that generates an ephemeral WireGuard keypair, runs a local HTTP callback server to receive the OAuth token, registers the keypair with the server, then writes a standard WireGuard config and calls `wg-quick up`.

WireGuard itself has no concept of authentication — it only knows about public keys. These two binaries are the glue that gates key registration behind Google SSO.
