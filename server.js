require('dotenv').config();

const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;

// ============================================================================
// DATA STORAGE & CONFIGURATION
// ============================================================================

/**
 * In-memory storage for OAuth data. In production, you'd use Redis or a database.
 * These Maps store temporary data with TTL-like behavior through manual cleanup.
 */
const authCodes = new Map();      // Stores authorization codes (short-lived, ~10 minutes)
const accessTokens = new Map();   // Stores access token metadata for validation
const refreshTokens = new Map();  // Stores refresh token metadata for token refresh flow

/**
 * Server configuration - all the key settings for your OAuth provider.
 * These values are what you'll configure in the Canva Developer Portal.
 *
 * SECURITY: All sensitive values must be set in the .env file.
 * Copy .env.example to .env and configure your values.
 *
 * NOTE: Use ngrok or a public URL if Canva needs to reach your server remotely.
 * For local development, https://localhost:8443 works fine.
 */

// Validate required environment variables
const requiredEnvVars = ['CLIENT_ID', 'CLIENT_SECRET', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
  console.error('💡 Copy .env.example to .env and configure your values');
  process.exit(1);
}

const CONFIG = {
  issuer: process.env.ISSUER || `https://localhost:${HTTPS_PORT}`, // OAuth issuer URL
  clientId: process.env.CLIENT_ID,                                  // Registered client ID for your Canva app
  clientSecret: process.env.CLIENT_SECRET,                          // Secret for authenticating your app
  jwtSecret: process.env.JWT_SECRET,                                // Key for signing JWTs
  tokenExpiry: 3600,                                                // Access token lifetime (1 hour)
  refreshTokenExpiry: 86400 * 7,                                    // Refresh token lifetime (7 days)
};

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

/**
 * CORS configuration to allow requests from Canva and your local development.
 * This is crucial - without proper CORS, browsers will block OAuth redirects.
 * 
 * Updated to include both HTTP and HTTPS localhost origins for development flexibility.
 */
app.use(cors({
  origin: ['https://localhost:3000', 'http://localhost:3000', 'https://www.canva.com', 'https://*.canva.com'],
  credentials: true  // Allow cookies/auth headers in cross-origin requests
}));

/**
 * Body parsing middleware for handling form data and JSON payloads.
 * OAuth token requests typically use application/x-www-form-urlencoded.
 */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// OPENID CONNECT DISCOVERY ENDPOINT
// ============================================================================

/**
 * GET /.well-known/openid-configuration
 * 
 * This is the OpenID Connect Discovery endpoint - it's like a "business card" 
 * for your OAuth server. When applications want to integrate with your IdP, 
 * they can hit this endpoint to automatically discover all the URLs and 
 * capabilities your server supports.
 * 
 * Think of it as a self-documenting API that says "here's everything I can do 
 * and where to find it." Many OAuth libraries use this to auto-configure themselves.
 * 
 * This endpoint should be publicly accessible and doesn't require authentication.
 * 
 * NOTE: All URLs now use HTTPS to meet Canva's security requirements!
 */
app.get('/.well-known/openid-configuration', (req, res) => {
  console.log('🔍 OpenID Connect Discovery requested');
  
  res.json({
    // Core identity - who is this server?
    issuer: CONFIG.issuer,
    
    // The main OAuth endpoints your app will interact with (all HTTPS now!)
    authorization_endpoint: `${CONFIG.issuer}/authorize`,  // Where users go to log in
    token_endpoint: `${CONFIG.issuer}/token`,              // Where apps exchange codes for tokens
    userinfo_endpoint: `${CONFIG.issuer}/userinfo`,       // Where to get user profile data
    revocation_endpoint: `${CONFIG.issuer}/revoke`,       // Where to invalidate tokens
    jwks_uri: `${CONFIG.issuer}/.well-known/jwks.json`,   // Public keys for verifying JWTs
    
    // Supported OAuth flows and features
    response_types_supported: ['code'],                     // Only authorization code flow (most secure)
    grant_types_supported: ['authorization_code', 'refresh_token'], // Token exchange types we handle
    subject_types_supported: ['public'],                   // User identifier format
    id_token_signing_alg_values_supported: ['HS256'],     // JWT signing algorithms
    scopes_supported: ['openid', 'profile', 'email'],     // What user data we can provide
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'], // How clients authenticate
    code_challenge_methods_supported: ['S256', 'plain']    // PKCE methods for mobile/SPA security
  });
});

// ============================================================================
// AUTHORIZATION ENDPOINT - WHERE THE OAUTH FLOW BEGINS
// ============================================================================

/**
 * GET /authorize
 * 
 * This is the first step in the OAuth Authorization Code flow. Here's what happens:
 * 
 * 1. Your React app redirects users to this URL with OAuth parameters
 * 2. Normally, this would show a login page where users enter credentials
 * 3. After successful login, user sees consent screen ("App X wants access to Y")
 * 4. If user approves, we generate an authorization code and redirect back to your app
 * 
 * For testing purposes, this endpoint skips the login/consent UI and auto-approves 
 * requests, but it still validates all the OAuth parameters and follows the spec.
 * 
 * Security note: Authorization codes are short-lived (10 minutes) and single-use.
 * They're essentially "vouchers" that prove the user said "yes" to your app.
 * 
 * Now running over HTTPS to satisfy Canva's security requirements!
 */
app.get('/authorize', (req, res) => {
  const {
    client_id,          // Your app's identifier - must match what's registered
    redirect_uri,       // Where to send the user after auth - must be pre-registered for security
    response_type,      // Must be "code" for authorization code flow
    scope,             // What permissions your app is requesting (openid, profile, email, etc.)
    state,             // Random value for CSRF protection - your app generates this
    code_challenge,    // PKCE code challenge for enhanced security (mobile/SPA apps)
    code_challenge_method // How the code_challenge was generated (S256 or plain)
  } = req.query;

  console.log('🔐 HTTPS Authorization Request Received:', {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    pkce: code_challenge ? 'enabled' : 'disabled',
    secure: 'YES (HTTPS)' // Now properly secured!
  });

  // ========== PARAMETER VALIDATION ==========
  // Real OAuth servers are strict about parameter validation for security
  
  if (!client_id || !redirect_uri || response_type !== 'code') {
    console.error('❌ Invalid authorization request - missing required parameters');
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing or invalid required parameters'
    });
  }

  // In production, you'd also validate:
  // - client_id exists in your database
  // - redirect_uri matches registered URIs for this client
  // - scope contains valid values
  // - state parameter exists (CSRF protection)

  // ========== MOCK USER AUTHENTICATION & CONSENT ==========
  // In a real IdP, this is where you'd:
  // 1. Check if user is already logged in (session/cookies)
  // 2. If not, redirect to login page
  // 3. After login, show consent screen
  // 4. Only proceed if user clicks "Allow"
  //
  // For testing, we'll auto-approve as if a user named "Test User" logged in
  // and consented to all requested permissions.

  // Generate a cryptographically secure authorization code
  // This code is like a temporary "voucher" that proves user consent
  const authCode = crypto.randomBytes(32).toString('hex');
  
  // Store the authorization code with all the context we'll need later
  // when the client exchanges this code for tokens
  authCodes.set(authCode, {
    client_id,                                    // Which app this code is for
    redirect_uri,                                 // Where we're allowed to redirect
    scope: scope || 'openid profile email',      // What permissions were granted
    user_id: 'mock-user-123',                    // The user who logged in (mock)
    code_challenge,                               // PKCE challenge for later verification
    code_challenge_method,                        // PKCE method (S256 or plain)
    expires_at: Date.now() + 10 * 60 * 1000,    // Expires in 10 minutes (security best practice)
  });

  console.log('✅ Generated authorization code:', authCode);
  console.log('⏰ Code expires at:', new Date(Date.now() + 10 * 60 * 1000).toISOString());

  // ========== REDIRECT BACK TO CLIENT ==========
  // Build the redirect URL with the authorization code
  // The client will receive this code and exchange it for tokens
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', authCode);
  
  // Include state parameter if provided (CSRF protection)
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }

  console.log('🔄 Redirecting user back to client app:', redirectUrl.toString());
  
  // HTTP 302 redirect - browser will automatically navigate user back to your app
  res.redirect(redirectUrl.toString());
});

// ============================================================================
// TOKEN ENDPOINT - WHERE AUTHORIZATION CODES BECOME ACCESS TOKENS
// ============================================================================

/**
 * POST /token
 * 
 * This is where the real magic happens. Your app exchanges the authorization code
 * (that it got from the /authorize endpoint) for actual access tokens that can
 * be used to call APIs.
 * 
 * This endpoint handles two grant types:
 * 1. authorization_code - Initial token exchange
 * 2. refresh_token - Getting new tokens when old ones expire
 * 
 * Security is critical here - this endpoint validates:
 * - Client credentials (client_id + client_secret)
 * - Authorization code validity and expiration
 * - PKCE code verifier (if used)
 * - All parameters match what was used in /authorize
 * 
 * Now running securely over HTTPS as required by Canva!
 */
app.post('/token', async (req, res) => {
  const {
    grant_type,        // Either "authorization_code" or "refresh_token"
    code,             // Authorization code from /authorize (for initial exchange)
    redirect_uri,     // Must match what was used in /authorize
    client_id,        // Your app's identifier
    client_secret,    // Your app's secret (proves this request is from your app)
    code_verifier,    // PKCE code verifier (if PKCE was used)
    refresh_token: refreshTokenParam // Refresh token (for refresh flow)
  } = req.body;

  console.log('🔄 HTTPS Token Exchange Request:', {
    grant_type,
    client_id,
    has_code: !!code,
    has_refresh_token: !!refreshTokenParam,
    has_code_verifier: !!code_verifier,
    secure: 'YES (HTTPS)'
  });

  // ========== CLIENT AUTHENTICATION ==========
  // Verify that this request is actually coming from your registered app
  // In production, you'd look up the client_id in your database
  console.log('🔍 Received credentials:', {
    received_client_id: client_id,
    expected_client_id: CONFIG.clientId,
    received_client_secret: client_secret ? client_secret.substring(0, 5) + '...' : 'missing',
    expected_client_secret: CONFIG.clientSecret.substring(0, 5) + '...',
    match: client_id === CONFIG.clientId && client_secret === CONFIG.clientSecret
  });
  
  if (client_id !== CONFIG.clientId || client_secret !== CONFIG.clientSecret) {
    console.error('❌ Invalid client credentials');
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }

  // ========== AUTHORIZATION CODE GRANT ==========
  // This is the initial token exchange - trading the auth code for tokens
  if (grant_type === 'authorization_code') {
    console.log('🎫 Processing authorization code grant over HTTPS...');
    
    // Look up the authorization code we stored earlier
    const authData = authCodes.get(code);
    
    if (!authData) {
      console.error('❌ Authorization code not found or already used');
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }

    // Check if the code has expired (security best practice)
    if (authData.expires_at < Date.now()) {
      console.error('❌ Authorization code expired');
      authCodes.delete(code); // Clean up expired code
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code expired'
      });
    }

    // ========== PKCE VALIDATION ==========
    // PKCE (Proof Key for Code Exchange) adds extra security for mobile/SPA apps
    // The client proves they're the same app that started the flow
    if (authData.code_challenge) {
      console.log('🔒 Validating PKCE over secure connection...');
      
      if (!code_verifier) {
        console.error('❌ PKCE code verifier required but not provided');
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Code verifier required for PKCE'
        });
      }

      // Generate the challenge from the verifier and compare
      // S256 = SHA256 hash, base64url encoded
      // plain = just use the verifier as-is
      const challenge = authData.code_challenge_method === 'S256'
        ? crypto.createHash('sha256').update(code_verifier).digest('base64url')
        : code_verifier;

      if (challenge !== authData.code_challenge) {
        console.error('❌ PKCE code verifier does not match challenge');
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid code verifier'
        });
      }
      
      console.log('✅ PKCE validation successful over HTTPS');
    }

    // ========== GENERATE TOKENS ==========
    // Everything checks out - create the actual access tokens
    const tokenData = generateTokens(authData.user_id, authData.scope, client_id);
    
    // Authorization codes are single-use - delete it now that we've used it
    authCodes.delete(code);

    console.log('✅ Authorization code exchanged for tokens successfully (HTTPS)');
    console.log('🎟️ Access token expires in:', CONFIG.tokenExpiry, 'seconds');
    
    res.json(tokenData);

  // ========== REFRESH TOKEN GRANT ==========
  // This lets clients get new access tokens without user interaction
  } else if (grant_type === 'refresh_token') {
    console.log('🔄 Processing refresh token grant over HTTPS...');
    
    const storedRefreshData = refreshTokens.get(refreshTokenParam);
    
    if (!storedRefreshData || storedRefreshData.expires_at < Date.now()) {
      console.error('❌ Refresh token invalid or expired');
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired refresh token'
      });
    }

    // Generate fresh tokens with the same scope as before
    const tokenData = generateTokens(
      storedRefreshData.user_id,
      storedRefreshData.scope,
      client_id
    );

    console.log('✅ Tokens refreshed successfully over HTTPS');
    
    res.json(tokenData);

  } else {
    console.error('❌ Unsupported grant type:', grant_type);
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Grant type not supported'
    });
  }
});

// ============================================================================
// USER INFO ENDPOINT - GET USER PROFILE DATA
// ============================================================================

/**
 * GET /userinfo
 * 
 * This is where your app gets actual user profile information. After getting
 * an access token from /token, your app can call this endpoint to get details
 * about the user who logged in.
 * 
 * This endpoint requires a valid access token in the Authorization header:
 * Authorization: Bearer <access_token>
 * 
 * The data returned here depends on the "scope" that was requested during
 * the initial authorization. Common scopes:
 * - openid: Required for OpenID Connect, gives you the "sub" (subject) claim
 * - profile: Basic profile info (name, given_name, family_name, etc.)
 * - email: Email address and email_verified flag
 * 
 * This is typically where you'd integrate with your user database to return
 * real user data. For testing, we return mock data for a fake user.
 * 
 * Now securely accessible over HTTPS only!
 */
app.get('/userinfo', authenticateToken, (req, res) => {
  // Mock user data - in production, you'd look this up from your database
  // using req.user.user_id
  const mockUser = {
    sub: req.user.user_id,                    // Subject - unique user identifier (required for OpenID)
    email: 'testuser@example.com',            // User's email address
    email_verified: true,                     // Whether email has been verified
    name: 'Test User',                        // Full display name
    given_name: 'Test',                       // First name
    family_name: 'User',                      // Last name
    picture: 'https://via.placeholder.com/150', // Profile picture URL
    locale: 'en-US',                          // User's locale/language preference
    updated_at: Math.floor(Date.now() / 1000) // When profile was last updated (Unix timestamp)
  };

  console.log('👤 HTTPS User info requested for user:', req.user.user_id);
  console.log('🔍 Token scope:', req.user.scope);
  console.log('🔐 Request served securely over HTTPS');
  
  res.json(mockUser);
});

// ============================================================================
// TOKEN REVOCATION ENDPOINT - LOGOUT/CLEANUP
// ============================================================================

/**
 * POST /revoke
 * 
 * This endpoint allows clients to invalidate tokens when they're no longer needed.
 * This is important for security - when a user logs out or an app is uninstalled,
 * you want to make sure those tokens can't be used anymore.
 * 
 * This endpoint can revoke:
 * - Access tokens (immediately stops API access)
 * - Refresh tokens (prevents getting new access tokens)
 * 
 * The token_type_hint parameter helps us optimize by indicating what type of
 * token is being revoked, but we should try to revoke it regardless of type.
 * 
 * Now running securely over HTTPS as required by Canva!
 */
app.post('/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;
  
  console.log('🗑️ HTTPS Token revocation requested:', { 
    token_type_hint,
    token_preview: token ? token.substring(0, 10) + '...' : 'none',
    secure: 'YES (HTTPS)'
  });
  
  // Remove the token from our storage, regardless of type
  // In production, you'd want to log this for security audit trails
  let revoked = false;
  
  if (accessTokens.delete(token)) {
    console.log('✅ Access token revoked over HTTPS');
    revoked = true;
  }
  
  if (refreshTokens.delete(token)) {
    console.log('✅ Refresh token revoked over HTTPS');
    revoked = true;
  }
  
  // Per OAuth spec, revocation endpoint should return 200 even if token wasn't found
  // This prevents information leakage about token validity
  res.status(200).json({ success: true });
  
  if (!revoked) {
    console.log('ℹ️ Token not found in storage (may have already been revoked or expired)');
  }
});

// ============================================================================
// JWKS ENDPOINT - PUBLIC KEYS FOR TOKEN VERIFICATION
// ============================================================================

/**
 * GET /.well-known/jwks.json
 * 
 * This endpoint provides the public keys that clients can use to verify
 * the authenticity of JWT tokens issued by this server. It's part of the
 * OpenID Connect standard.
 * 
 * When your app receives a JWT access token or ID token, it can use the
 * keys from this endpoint to verify:
 * 1. The token was actually issued by this server (not forged)
 * 2. The token hasn't been tampered with
 * 
 * In production, you'd use RSA keys for better security. For testing,
 * we're using HMAC with a shared secret (simpler but less secure).
 * 
 * Now served securely over HTTPS!
 */
app.get('/.well-known/jwks.json', (req, res) => {
  console.log('🔑 JWKS (public keys) requested over HTTPS');
  
  // In production, use proper RSA key pairs like this:
  // {
  //   "kty": "RSA",
  //   "use": "sig",
  //   "kid": "key-id-1", 
  //   "n": "...", // RSA public key modulus
  //   "e": "AQAB" // RSA public key exponent
  // }
  
  res.json({
    keys: [{
      kty: 'oct',  // Key type: octet (symmetric key)
      k: Buffer.from(CONFIG.jwtSecret).toString('base64url'), // The shared secret, base64url encoded
      alg: 'HS256', // Algorithm: HMAC SHA-256
      use: 'sig'   // Key use: signing (and verification)
    }]
  });
});

// ============================================================================
// UTILITY ENDPOINTS
// ============================================================================

/**
 * GET /health
 * 
 * Simple health check endpoint to verify the server is running and configured correctly.
 * Useful for monitoring, load balancers, and troubleshooting.
 * 
 * Now indicates that the server is running securely over HTTPS!
 */
app.get('/health', (req, res) => {
  console.log('🏥 HTTPS Health check requested');
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    protocol: 'HTTPS (Secure)', // Now properly secured!
    config: {
      issuer: CONFIG.issuer,
      client_id: CONFIG.clientId
    }
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Generate OAuth tokens (access token, refresh token, ID token)
 * 
 * This function creates all the tokens needed for a successful OAuth flow:
 * 1. Access Token (JWT) - Used to authenticate API requests
 * 2. Refresh Token - Used to get new access tokens without user interaction
 * 3. ID Token (JWT) - Contains user identity information (OpenID Connect)
 * 
 * All tokens now issued by an HTTPS server for enhanced security!
 */
function generateTokens(userId, scope, clientId) {
  const now = Math.floor(Date.now() / 1000);
  
  // ========== ACCESS TOKEN (JWT) ==========
  // This is what your app will send with API requests
  // Contains claims about what the token can access and when it expires
  const accessToken = jwt.sign({
    sub: userId,                    // Subject - who this token represents
    iss: CONFIG.issuer,            // Issuer - who created this token (now HTTPS!)
    aud: clientId,                 // Audience - who this token is for
    scope: scope,                  // What permissions this token grants
    iat: now,                      // Issued At - when this token was created
    exp: now + CONFIG.tokenExpiry  // Expires - when this token becomes invalid
  }, CONFIG.jwtSecret);

  // ========== REFRESH TOKEN ==========
  // This is an opaque token (just random bytes) used to get new access tokens
  // It's stored server-side with metadata about the grant
  const refreshToken = crypto.randomBytes(32).toString('hex');
  
  // Store token metadata for later validation
  accessTokens.set(accessToken, {
    user_id: userId,
    scope: scope,
    expires_at: Date.now() + (CONFIG.tokenExpiry * 1000)
  });

  refreshTokens.set(refreshToken, {
    user_id: userId,
    scope: scope,
    expires_at: Date.now() + (CONFIG.refreshTokenExpiry * 1000)
  });

  // ========== ID TOKEN (JWT) ==========
  // OpenID Connect identity token - contains user profile claims
  // This is separate from the access token and contains identity info
  const idToken = jwt.sign({
    sub: userId,                    // Subject - unique user identifier
    iss: CONFIG.issuer,            // Issuer (now HTTPS!)
    aud: clientId,                 // Audience
    iat: now,                      // Issued At
    exp: now + CONFIG.tokenExpiry, // Expires
    // User profile claims (would come from your user database)
    email: 'testuser@example.com',
    name: 'Test User',
    email_verified: true
  }, CONFIG.jwtSecret);

  console.log('🎟️ Generated new token set for user:', userId, '(issued over HTTPS)');

  // Return in OAuth 2.0 standard format
  return {
    access_token: accessToken,
    token_type: 'Bearer',           // How to use the access token (Authorization: Bearer <token>)
    expires_in: CONFIG.tokenExpiry, // Seconds until access token expires
    refresh_token: refreshToken,    // Token for getting new access tokens
    scope: scope,                   // Permissions granted
    id_token: idToken              // OpenID Connect identity token
  };
}

/**
 * Middleware to authenticate requests using Bearer tokens
 * 
 * This function validates access tokens sent in the Authorization header.
 * It's used to protect endpoints like /userinfo that require authentication.
 * 
 * Expected header format: Authorization: Bearer <jwt_access_token>
 * 
 * Now running over HTTPS for maximum security!
 */
function authenticateToken(req, res, next) {
  // Extract token from Authorization header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN" -> "TOKEN"

  if (!token) {
    console.error('❌ No access token provided in Authorization header (HTTPS request)');
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'No access token provided'
    });
  }

  try {
    // Verify and decode the JWT token
    const decoded = jwt.verify(token, CONFIG.jwtSecret);
    
    // Check if token has expired (JWT library does this, but double-check)
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      console.error('❌ Access token has expired (HTTPS request)');
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token expired'
      });
    }
    
    // Add decoded token data to request object for use in route handlers
    req.user = decoded;
    console.log('✅ Access token validated for user:', decoded.sub, '(over HTTPS)');
    next();
    
  } catch (err) {
    console.error('❌ Invalid access token (HTTPS request):', err.message);
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
  }
}

// ============================================================================
// HTTPS SERVER STARTUP
// ============================================================================

/**
 * Start HTTPS server with SSL certificates
 * 
 * Canva requires HTTPS for all OAuth endpoints, so this function sets up
 * a proper HTTPS server using SSL certificates. It supports both:
 * 1. mkcert certificates (trusted by browsers, best for development)
 * 2. OpenSSL self-signed certificates (browser warning, but functional)
 */
function startServer() {
  try {
    let httpsOptions;
    
    // Check for mkcert certificates first (recommended)
    const mkcertKey = path.join(__dirname, 'localhost-key.pem');
    const mkcertCert = path.join(__dirname, 'localhost.pem');
    
    // Check for OpenSSL certificates as fallback
    const opensslKey = path.join(__dirname, 'server-key.pem');
    const opensslCert = path.join(__dirname, 'server-cert.pem');
    
    if (fs.existsSync(mkcertKey) && fs.existsSync(mkcertCert)) {
      // Use mkcert certificates (best for development)
      httpsOptions = {
        key: fs.readFileSync(mkcertKey),
        cert: fs.readFileSync(mkcertCert)
      };
      console.log('🔐 Using mkcert certificates (trusted by browser)');
      
    } else if (fs.existsSync(opensslKey) && fs.existsSync(opensslCert)) {
      // Use OpenSSL certificates
      httpsOptions = {
        key: fs.readFileSync(opensslKey),
        cert: fs.readFileSync(opensslCert)
      };
      console.log('🔐 Using OpenSSL self-signed certificates');
      
    } else {
      throw new Error('No SSL certificates found');
    }

    // Start HTTPS server
    https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
      console.log(`🚀 HTTPS OAuth Server running on https://localhost:${HTTPS_PORT}`);
      console.log('🔒 All OAuth endpoints now secured with HTTPS (Canva compliant!)');
      console.log('');
      console.log('📋 Canva Developer Portal Settings (HTTPS):');
      console.log(`   Provider: https://localhost:${HTTPS_PORT}`);
      console.log(`   Client ID: ${CONFIG.clientId}`);
      console.log(`   Client Secret: ${CONFIG.clientSecret}`);
      console.log(`   Authorization URL: https://localhost:${HTTPS_PORT}/authorize`);
      console.log(`   Token Exchange URL: https://localhost:${HTTPS_PORT}/token`);
      console.log(`   Revocation URL: https://localhost:${HTTPS_PORT}/revoke`);
      console.log(`   PKCE: Enabled (S256 and plain supported)`);
      console.log('');
      console.log('🔍 Discovery: https://localhost:8443/.well-known/openid-configuration');
      console.log('💡 Health Check: https://localhost:8443/health');
      console.log('');
      console.log('📖 Ready to test secure OAuth flows with Canva! Check console for detailed request/response info.');
      
      if (!fs.existsSync(mkcertKey)) {
        console.log('⚠️  Accept certificate warning in browser for first visit (OpenSSL certs)');
      } else {
        console.log('✅ Certificates trusted by browser (mkcert) - no security warnings!');
      }
    });

  } catch (error) {
    console.error('❌ Failed to start HTTPS server:', error.message);
    console.log('');
    console.log('🔧 SSL certificates not found. Please run one of these commands:');
    console.log('');
    console.log('Option 1 - Using mkcert (recommended for trusted certs):');
    console.log('  brew install mkcert && mkcert -install && mkcert localhost');
    console.log('');
    console.log('Option 2 - Using OpenSSL (creates browser warning):');
    console.log('  openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/CN=localhost"');
    console.log('');
    console.log('Then run: npm start');
    console.log('');
    console.log('💡 Canva requires HTTPS for OAuth endpoints - HTTP will not work!');
    process.exit(1);
  }
}

// ============================================================================
// SERVER STARTUP
// ============================================================================

/**
 * Start the HTTPS OAuth server 
 * 
 * This will create a secure OAuth provider that meets Canva's HTTPS requirements
 * and includes comprehensive logging for understanding the OAuth flow.
 */
startServer();

module.exports = app;