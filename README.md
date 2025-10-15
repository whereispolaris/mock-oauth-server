# Mock OAuth Server

A fully-featured mock OAuth 2.0 / OpenID Connect server for testing Canva integrations and other OAuth workflows. This server implements the authorization code flow with PKCE support and provides all necessary endpoints for a complete OAuth provider.

## Features

- **OAuth 2.0 Authorization Code Flow** with PKCE support
- **OpenID Connect** compliant with discovery endpoint
- **HTTPS support** (required for Canva integrations)
- **JWT-based access tokens** and ID tokens
- **Refresh token** support for long-lived sessions
- **Token revocation** endpoint for secure logout
- **User info endpoint** with mock user data
- **Comprehensive logging** for debugging OAuth flows

## Prerequisites

- Node.js 14+ and npm
- SSL certificates for HTTPS (see setup below)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/whereispolaris/mock-oauth-server.git
cd mock-oauth-server
```

2. Install dependencies:
```bash
npm install
```

3. Generate SSL certificates (required for HTTPS):

**Option 1: Using mkcert (recommended - trusted by browsers)**
```bash
brew install mkcert
mkcert -install
mkcert localhost
```

**Option 2: Using OpenSSL (creates browser security warning)**
```bash
openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/CN=localhost"
```

4. Configure environment variables (optional):
```bash
cp .env.example .env
# Edit .env with your values
```

## Configuration

The server can be configured using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3001 | HTTP port (legacy, HTTPS recommended) |
| `HTTPS_PORT` | 8443 | HTTPS port |
| `CLIENT_ID` | canva-test-client | OAuth client ID |
| `CLIENT_SECRET` | canva-secret-key-12345 | OAuth client secret |
| `JWT_SECRET` | mock-jwt-secret-key | Secret key for signing JWTs |
| `ISSUER` | https://localhost:8443 | OAuth issuer URL |

**Security Note:** Change the default secrets in production or when exposing this server publicly!

## Usage

Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

The server will start on `https://localhost:8443` by default.

## Endpoints

### Discovery & Health

- `GET /.well-known/openid-configuration` - OpenID Connect discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set for token verification
- `GET /health` - Health check endpoint

### OAuth Flow

- `GET /authorize` - Authorization endpoint (start OAuth flow)
- `POST /token` - Token exchange endpoint
- `GET /userinfo` - User profile endpoint (requires access token)
- `POST /revoke` - Token revocation endpoint

## Testing with Canva

1. Start the server with HTTPS enabled
2. In the Canva Developer Portal, configure your app with:
   - **Provider**: `https://localhost:8443`
   - **Client ID**: `canva-test-client` (or your configured value)
   - **Client Secret**: `canva-secret-key-12345` (or your configured value)
   - **Authorization URL**: `https://localhost:8443/authorize`
   - **Token Exchange URL**: `https://localhost:8443/token`
   - **Revocation URL**: `https://localhost:8443/revoke`
   - **PKCE**: Enabled

3. For ngrok tunneling (if testing remotely):
```bash
ngrok http 8443
# Update the ISSUER environment variable with your ngrok URL
```

## Example OAuth Flow

1. **Authorization Request**:
```
https://localhost:8443/authorize?
  client_id=canva-test-client&
  redirect_uri=https://your-app.com/callback&
  response_type=code&
  scope=openid profile email&
  state=random-state-value&
  code_challenge=CHALLENGE&
  code_challenge_method=S256
```

2. **Token Exchange**:
```bash
curl -X POST https://localhost:8443/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=canva-test-client" \
  -d "client_secret=canva-secret-key-12345" \
  -d "redirect_uri=https://your-app.com/callback" \
  -d "code_verifier=VERIFIER"
```

3. **Get User Info**:
```bash
curl https://localhost:8443/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Mock User Data

The server returns the following mock user data:
- **User ID**: mock-user-123
- **Email**: testuser@example.com
- **Name**: Test User
- **Email Verified**: true

## Development

The server uses in-memory storage for all OAuth data. This means:
- All tokens and codes are lost when the server restarts
- No database required
- Perfect for testing and development
- Not suitable for production use

## Troubleshooting

### Certificate Errors
If you see "certificate not trusted" errors:
- Use mkcert instead of OpenSSL for trusted certificates
- Accept the security warning in your browser for OpenSSL certificates

### CORS Errors
- Ensure your client app's origin is listed in the CORS configuration
- Check browser console for specific CORS errors

### Token Exchange Fails
- Verify client_id and client_secret match your configuration
- Check that authorization codes haven't expired (10-minute lifetime)
- Ensure all parameters match what was used in the /authorize request

## License

MIT

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## Security Notice

This is a **mock OAuth server for development and testing only**. Do not use in production without:
- Implementing proper user authentication
- Using a real database for token storage
- Adding rate limiting and abuse prevention
- Using proper RSA keys instead of HMAC for JWT signing
- Implementing comprehensive input validation
- Adding audit logging
- Following OAuth 2.0 security best practices
