import type { JwtPayload } from 'jsonwebtoken'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: unknown
    }
  }
}

export type KeyPairSettings = {
  secretKey: string
  publicKey: string
}

export type AuthSettings = {
  accessTokenTTL: number
  refreshTokenTTLInDays: number
  issuer: string
  onLoginFailed?: (e: LoginFailedEvent) => Promise<void>
  onLoginSuccess?: (e: LoginSuccessEvent) => Promise<void>
}

type LoginFailedEvent = {
  username: string
  errorType: 'invalid_username' | 'invalid_password' | string
  client: string
  ipAddress: string
}

type LoginSuccessEvent = {
  userId: string
  username: string
  client: string
  ipAddress: string
}

export type PluginSettings = AuthSettings & {
  keys: KeyPairSettings
  dataProvider: DataProvider
}

export interface AppJwtPayload extends JwtPayload {
  username: string
  auth_time: number
}

export type TokenPair = {
  accessToken: string
  refreshToken: string
}

export type CreateTokenPayload = {
  sub: string
  username: string
  auth_time: number
}

export type StoreRefreshTokenDto = {
  token: string
  tokenHash: string
  userId: string
  jwtId: string
  expiresAt: Date
}

export type RefreshTokenData = {
  userId: string
  jwtId: string
  expiresAt: Date
  isUsed: boolean
  revokedAt?: Date | null
}

export type DataProvider = {
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
