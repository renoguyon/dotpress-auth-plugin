# Dotpress Auth

Authentication plugin for [dotpress](https://www.npmjs.com/package/dotpress) library using JWT tokens.
You can use Prisma or any other ORM and easily connect it using the plugin DataProvider interface.


[Full documentation here](https://dotpress.dev)

---

## Quick Start

### 1. Install

```bash
npm install @dotpress/auth
```

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

- keys.publicKey (string, required): public RSA key to validate JWT tokens
- keys.secretKey (string, required): private RSA key to generate JWT tokens
- dataProvider (DataProvider, required): set of functions to store and retrieve data (see below)
- accessTokenTTL (optional, default: 3600): Time-to-live, in seconds, for access tokens
- refreshTokenTTLInDays (optional, default: 14): Time-to-live, in days, for refresh tokens
- issuer (string, optional but recommended): Domain of your app or auth service
- onLoginFailed (optional): Event handler triggered on failed logins
- onLoginSuccess (optional): Event handler triggered on success logins

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

## Endpoints

### `POST /auth/login`

Authenticate a user and generate tokens.

Request Body:
- username: string
- password: string
- client: optional user agent string

Response:
- userId: string
- accessToken: string
- refreshToken: string

Returns 401 on failed login.

### `POST /auth/refresh`

Refresh tokens using previous token pair.

Request Body:
- accessToken: Previous access token, can be expired or still valid
- refreshToken: Refresh token, must be valid, not used, not revoked

Response:
- userId: string
- accessToken: string
- refreshToken: string

Returns 401 if tokens are not valid.

### `POST /auth/logout`

Revoke tokens for current authenticated user.

Response:
- 200 OK on success
- 401 if user is not authenticated

### `GET /auth/me`

Get current authenticated user

Response:
- User object if user is authenticated
- 401 if user is not authenticated


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
