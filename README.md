# Dotpress Auth

Authentication plugin for [dotpress](https://www.npmjs.com/package/dotpress) library using JWT tokens.
You can use Prisma or any other ORM and easily connect it using the plugin DataProvider interface.


[Full documentation here](https://dotpress.dev)

---

## Quick Start

### 1. Install

```bash
npm install @dotpress/auth cookie-parser
npm install --save-dev @types/cookie-parser
```

**Note:** `cookie-parser` is required as a peer dependency if you want to use cookie-based authentication.

### 2. Register your plugin

```ts
// index.ts
import { createApp, defineRoute } from 'dotpress'
import { configurePlugin } from '@dotpress/auth'

const authPlugin = configurePlugin({
  // See configuration object below
})

const app = await createApp({
  plugins: [authPlugin]
})

app.listen(3000, () => {
  console.log('Server listening on port 3000')
})
```

### 3. Usage

The plugin will check and parse bearer token from Authorization header and will register the following routes (full API below)

- `POST /auth/login`
- `POST /auth/refresh`
- `GET /auth/me`
- `POST /auth/logout`

---

## Configuration object properties

- **keys.publicKey** (string, required): public RSA key to validate JWT tokens
- **keys.secretKey** (string, required): private RSA key to generate JWT tokens
- **dataProvider** (DataProvider, required): set of functions to store and retrieve data (see below)
- **accessTokenTTL** (optional, default: 3600): Time-to-live, in seconds, for access tokens
- **refreshTokenTTLInDays** (optional, default: 14): Time-to-live, in days, for refresh tokens
- **issuer** (string, optional but recommended): Domain of your app or auth service
- **cookies** (CookieSettings, optional): Cookie configuration for web authentication
- **onLoginFailed** (optional): Event handler triggered on failed logins
- **onLoginSuccess** (optional): Event handler triggered on success logins

### Cookie Settings

The `cookies` object supports the following properties:

```ts
type CookieSettings = {
  enabled?: boolean              // Enable cookie mode (default: false)
  httpOnly?: boolean             // HttpOnly flag (default: true)
  secure?: boolean               // Secure flag (default: true in production)
  sameSite?: 'strict' | 'lax' | 'none'  // SameSite policy (default: 'lax')
  domain?: string                // Cookie domain for cross-subdomain auth
  path?: string                  // Cookie path (default: '/')
  accessTokenName?: string       // Access token cookie name (default: 'dotpress_access_token')
  refreshTokenName?: string      // Refresh token cookie name (default: 'dotpress_refresh_token')
  accessTokenInCookie?: boolean  // Store access token in cookie (default: false)
}
```

**Example configuration for cross-subdomain authentication:**

```ts
const authPlugin = configurePlugin({
  keys: { /* ... */ },
  dataProvider: { /* ... */ },
  cookies: {
    enabled: true,
    domain: '.myapp.com',  // Works for app.myapp.com, www.myapp.com, etc.
    secure: true,
    sameSite: 'lax',
  }
})
```

### DataProvider type

```ts
type DataProvider = {
  storeRefreshToken: (payload: StoreRefreshTokenDto) => Promise<void>
  findRefreshToken: (tokenHash: string) => Promise<RefreshTokenData | undefined>
  markRefreshTokenAsUsed: (tokenHash: string) => Promise<void>
  revokeTokens: (userId: string) => Promise<void>
  findUserById: <TUser = Record<string, unknown>>(
    userId: string
  ) => Promise<TUser | undefined>
  findUserIdentifiers: (
    username: string
  ) => Promise<{ userId: string; passwordHash: string } | undefined>
}


type StoreRefreshTokenDto = {
  token: string
  tokenHash: string
  userId: string
  jwtId: string
  expiresAt: Date
}

type RefreshTokenData = {
  userId: string
  jwtId: string
  expiresAt: Date
  isUsed: boolean
  revokedAt?: Date | null
}
```

## Authentication Modes

This plugin supports two authentication modes that can coexist:

### Body Mode (Default)
Tokens are sent in request body. Suitable for mobile apps (Expo/React Native) and desktop apps (Electron).

### Cookie Mode
Tokens are stored in httpOnly cookies. Suitable for web applications (SPAs, SSR) for enhanced security against XSS attacks.

The plugin automatically detects which mode to use based on the request.

---

## Endpoints

### `POST /auth/login`

Authenticate a user and generate tokens.

**Request Body:**
- `username` (string, required): Username
- `password` (string, required): Password
- `client` (string, optional): User agent string for tracking
- `aud` (string, optional): Audience for role-based access control
- `mode` (enum: 'body' | 'cookie', optional): Authentication mode

**Response:**
```json
{
  "userId": "usr-123",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "3f7b2a8c1e...",
  "expiresIn": 3600,
  "expiresAt": "2025-11-02T15:30:00.000Z"
}
```

**Behavior:**
- If `mode: 'cookie'` is provided, tokens are also set as httpOnly cookies
- `accessToken` and `refreshToken` are always returned in the response body for flexibility
- Returns 401 on failed login

**Cookie Mode Example:**

```ts
// Client login request with cookie mode
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',  // Important for cookies!
  body: JSON.stringify({
    username: 'john@example.com',
    password: 'secret123',
    mode: 'cookie'
  })
})
```

### `POST /auth/refresh`

Refresh tokens using previous token pair. The plugin automatically detects the authentication mode.

**Request Body (Body Mode):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "3f7b2a8c1e..."
}
```

**Request Body (Cookie Mode):**
```json
{}
```
*Tokens are automatically extracted from cookies.*

**Response:**
```json
{
  "userId": "usr-123",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9a1b3c5d7f...",
  "expiresIn": 3600,
  "expiresAt": "2025-11-02T16:30:00.000Z"
}
```

**Behavior:**
- Automatically detects mode: checks cookies first, then falls back to body
- If cookies are present, new tokens are automatically set as cookies
- Old refresh token is marked as used (one-time use with rotation)
- Returns 401 if tokens are not valid

**Error Codes:**
- `NO_TOKENS_PROVIDED`: No tokens found in cookies or body
- `INVALID_REFRESH_TOKEN`: Refresh token is invalid or already used
- `EXPIRED_REFRESH_TOKEN`: Refresh token has expired

### `GET /auth/me`

Get current authenticated user.

**Request:**
No body required. Token is extracted from:
1. `Authorization: Bearer <token>` header (priority)
2. Cookie (if cookie mode is enabled and `accessTokenInCookie: true`)

**Response:**
```json
{
  "id": "usr-123",
  "username": "john@example.com",
  "email": "john@example.com",
  // ... other user fields
}
```

Returns 401 if user is not authenticated.

### `POST /auth/logout`

Revoke tokens for current authenticated user.

**Response:**
```json
{
  "success": true
}
```

**Behavior:**
- Revokes all refresh tokens for the user in the database
- Clears authentication cookies if cookie mode was used
- Returns 401 if user is not authenticated


## Multi-Platform Support

The plugin is designed to support multiple client types simultaneously:

| Client Type | Recommended Mode | Configuration |
|-------------|-----------------|---------------|
| React SPA | Cookie | `mode: 'cookie'` in login |
| Next.js SSR | Cookie | `mode: 'cookie'` + `domain: '.yourapp.com'` |
| React Native / Expo | Body | No `mode` parameter (default) |
| Electron | Body | No `mode` parameter (default) |

**Cross-subdomain authentication example:**

```ts
// API configuration (api.myapp.com)
const authPlugin = configurePlugin({
  cookies: {
    enabled: true,
    domain: '.myapp.com',  // Share cookies across subdomains
    secure: true,
    sameSite: 'lax',
  },
  // ... other settings
})

// CORS configuration
const app = await createApp({
  cors: {
    origin: [
      'https://app.myapp.com',
      'https://www.myapp.com',
    ],
    credentials: true,  // Required for cookies!
  },
  plugins: [authPlugin]
})
```

**Client-side fetch configuration:**

```ts
// Always include credentials for cookie mode
fetch('https://api.myapp.com/auth/login', {
  method: 'POST',
  credentials: 'include',  // Essential for cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password, mode: 'cookie' })
})
```

---

## Prisma schema examples

You will find below recommended schema for User and RefreshToken entities. Feel free to adapt them according to your needs.

```text
model User {
  id                    String                 @id @default(cuid())
  firstName             String?                @db.VarChar(100)
  lastName              String?                @db.VarChar(100)
  username              String                 @unique @db.VarChar(50)
  pwdHash               String                 @db.VarChar(200)
  email                 String                 @db.VarChar(200)
  role                  String                 @db.VarChar(50)
  createdAt             DateTime               @default(now())
  updatedAt             DateTime               @updatedAt

  @@map("users")
}

model RefreshToken {
  id        String    @id @default(cuid())
  userId    String    @db.VarChar(50)
  jwtId     String    @db.VarChar(100)
  tokenHash String    @unique @db.VarChar(100)
  expiresAt DateTime
  revokedAt DateTime?
  isUsed    Boolean
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  @@map("refresh_tokens")
}
```
