import jwt from 'jsonwebtoken'
import { randomBytes, createHash } from 'crypto'
import { getSettings } from './settings.js'
import { AppJwtPayload, TokenPair } from '../types/types.js'
import { generateUUID } from './generators.js'

type CreateTokenPayload = {
  sub: string
  username: string
  auth_time: number
  aud?: string
}

type CreatedAccessToken = {
  jwtId: string
  accessToken: string
}

type CreatedRefreshToken = {
  token: string
  tokenHash: string
}

type UserIdentifiers = {
  userId: string
  username: string
  aud?: string
}

export const createAccessTokenFromPayload = (
  payload: CreateTokenPayload
): CreatedAccessToken => {
  const jwtId = generateUUID()
  const settings = getSettings()

  const accessToken = jwt.sign(payload, settings.keys.secretKey, {
    algorithm: 'RS256',
    issuer: settings.issuer,
    expiresIn: settings.accessTokenTTL,
    jwtid: jwtId,
  })

  return {
    jwtId,
    accessToken,
  }
}

export const generateRefreshToken = (): CreatedRefreshToken => {
  const token = randomBytes(128).toString('hex')
  const tokenHash = createHash('sha256').update(token).digest('hex')

  return {
    token,
    tokenHash,
  }
}

/**
 * Generate a pair of access and refresh tokens for a given user
 */
export const generateTokensForUser = async ({
  userId,
  username,
  aud,
}: UserIdentifiers): Promise<TokenPair> => {
  const settings = getSettings()

  const { jwtId, accessToken } = generateAccessToken({ userId, username, aud })

  const { token: refreshToken, tokenHash: refreshTokenHash } =
    generateRefreshToken()

  await settings.dataProvider.storeRefreshToken({
    token: refreshToken,
    tokenHash: refreshTokenHash,
    userId,
    jwtId,
    expiresAt: addDaysFromNow(settings.refreshTokenTTLInDays),
  })

  return {
    accessToken,
    refreshToken,
  }
}

export const generateAccessToken = ({
  userId,
  username,
  aud,
}: UserIdentifiers): CreatedAccessToken => {
  return createAccessTokenFromPayload({
    sub: userId,
    username,
    auth_time: Math.floor(Date.now() / 1000),
    aud,
  })
}

const addDaysFromNow = (days: number): Date => {
  const now = new Date()
  now.setDate(now.getDate() + days)
  return now
}

/**
 * Regenerate a pair of token using a refresh token
 * Expired access token must be provided in order to validate userId and jwtId
 */
export const generateTokensFromRefreshToken = async ({
  accessToken,
  refreshToken,
}: TokenPair): Promise<TokenPair & { userId: string }> => {
  const settings = getSettings()

  const decodedToken: AppJwtPayload = jwt.verify(
    accessToken,
    settings.keys.publicKey,
    {
      ignoreExpiration: true,
    }
  ) as AppJwtPayload

  const userId = String(decodedToken.sub)
  const refreshTokenHash = createHash('sha256')
    .update(refreshToken)
    .digest('hex')

  const refreshTokenData =
    await settings.dataProvider.findRefreshToken(refreshTokenHash)

  if (
    !refreshTokenData ||
    refreshTokenData.revokedAt ||
    refreshTokenData.isUsed ||
    refreshTokenData.userId !== userId ||
    refreshTokenData.jwtId !== decodedToken.jti
  ) {
    throw new Error('Invalid_Refresh_Token')
  }

  if (refreshTokenData.expiresAt.getTime() <= Date.now()) {
    throw new Error('Expired_Refresh_Token')
  }

  const { jwtId, accessToken: newAccessToken } = createAccessTokenFromPayload({
    sub: userId,
    username: decodedToken.username,
    auth_time: decodedToken.auth_time,
    aud: (decodedToken.aud as string) || undefined,
  })

  const newRefreshToken = generateRefreshToken()
  await settings.dataProvider.storeRefreshToken({
    ...newRefreshToken,
    userId,
    jwtId,
    expiresAt: addDaysFromNow(settings.refreshTokenTTLInDays),
  })

  await settings.dataProvider.markRefreshTokenAsUsed(refreshTokenHash)

  return {
    userId,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken.token,
  }
}

export const validateAndDecodeAccessToken = (
  accessToken: string
): {
  userId: string
} => {
  const settings = getSettings()
  const { sub: userId } = jwt.verify(accessToken, settings.keys.publicKey)

  if (!userId) {
    throw new Error('Invalid_Access_Token')
  }

  return {
    userId: String(userId),
  }
}
