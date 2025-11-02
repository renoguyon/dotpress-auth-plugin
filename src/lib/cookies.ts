import type { Response, Request } from 'express'
import { getSettings } from './settings.js'
import type { CookieSettings, AuthMode } from '../types/types.js'

type ResolvedCookieSettings = Required<Omit<CookieSettings, 'domain'>> & {
  domain?: string
}

const DEFAULT_COOKIE_SETTINGS: ResolvedCookieSettings = {
  enabled: false,
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  accessTokenName: 'dotpress_access_token',
  refreshTokenName: 'dotpress_refresh_token',
  accessTokenInCookie: false,
  domain: undefined,
}

export const getCookieSettings = (): ResolvedCookieSettings => {
  const settings = getSettings()
  return {
    ...DEFAULT_COOKIE_SETTINGS,
    ...settings.cookies,
  }
}

/**
 * Set authentication cookies on the response
 */
export const setAuthCookies = (
  res: Response,
  tokens: { accessToken: string; refreshToken: string },
  expiresInSeconds: number
): void => {
  const cookieSettings = getCookieSettings()

  if (!cookieSettings.enabled) {
    return
  }

  const cookieOptions = {
    httpOnly: cookieSettings.httpOnly,
    secure: cookieSettings.secure,
    sameSite: cookieSettings.sameSite,
    path: cookieSettings.path,
    domain: cookieSettings.domain,
    maxAge: expiresInSeconds * 1000,
  }

  // Always set refresh token in cookie for 'cookie' mode
  res.cookie(
    cookieSettings.refreshTokenName,
    tokens.refreshToken,
    cookieOptions
  )

  // Optionally set access token in cookie
  if (cookieSettings.accessTokenInCookie) {
    res.cookie(
      cookieSettings.accessTokenName,
      tokens.accessToken,
      cookieOptions
    )
  }
}

/**
 * Clear authentication cookies
 */
export const clearAuthCookies = (res: Response): void => {
  const cookieSettings = getCookieSettings()

  if (!cookieSettings.enabled) {
    return
  }

  const cookieOptions = {
    httpOnly: cookieSettings.httpOnly,
    secure: cookieSettings.secure,
    sameSite: cookieSettings.sameSite,
    path: cookieSettings.path,
    domain: cookieSettings.domain,
  }

  res.clearCookie(cookieSettings.refreshTokenName, cookieOptions)

  if (cookieSettings.accessTokenInCookie) {
    res.clearCookie(cookieSettings.accessTokenName, cookieOptions)
  }
}

/**
 * Detect authentication mode from request
 * Priority: cookies first, then body
 */
export const detectAuthMode = (req: Request): AuthMode | null => {
  const cookieSettings = getCookieSettings()

  // Check if refresh token exists in cookies
  if (req.cookies?.[cookieSettings.refreshTokenName]) {
    return 'cookie'
  }

  // Check if refresh token exists in body
  if (req.body?.refreshToken) {
    return 'body'
  }

  return null
}

/**
 * Extract tokens from request based on detected mode
 */
export const extractTokensFromRequest = (
  req: Request
): { accessToken: string; refreshToken: string } | null => {
  const mode = detectAuthMode(req)
  const cookieSettings = getCookieSettings()

  if (mode === 'cookie') {
    const refreshToken = req.cookies?.[cookieSettings.refreshTokenName]
    const accessToken = cookieSettings.accessTokenInCookie
      ? req.cookies?.[cookieSettings.accessTokenName]
      : req.body?.accessToken

    if (!refreshToken || !accessToken) {
      return null
    }

    return { accessToken, refreshToken }
  }

  if (mode === 'body') {
    const { accessToken, refreshToken } = req.body || {}

    if (!accessToken || !refreshToken) {
      return null
    }

    return { accessToken, refreshToken }
  }

  return null
}

/**
 * Extract access token from request
 * Priority: Authorization header > cookie > body
 */
export const extractAccessToken = (req: Request): string | null => {
  // Priority 1: Authorization header
  const authHeader = req.headers.authorization
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.replace('Bearer ', '')
  }

  const cookieSettings = getCookieSettings()

  // Priority 2: Cookie (if enabled)
  if (
    cookieSettings.enabled &&
    cookieSettings.accessTokenInCookie &&
    req.cookies?.[cookieSettings.accessTokenName]
  ) {
    return req.cookies[cookieSettings.accessTokenName]
  }

  // Priority 3: Body
  if (req.body?.accessToken) {
    return req.body.accessToken
  }

  return null
}

/**
 * Calculate expiration timestamp
 */
export const calculateExpiration = (
  expiresInSeconds: number
): { expiresIn: number; expiresAt: string } => {
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000)

  return {
    expiresIn: expiresInSeconds,
    expiresAt: expiresAt.toISOString(),
  }
}
