import type { PluginAPI } from 'dotpress'
import { unauthorizedError, internalError } from 'dotpress'
import bcrypt from 'bcryptjs'
import { getSettings } from './settings.js'
import { getRequestIp } from './ip.js'
import {
  generateTokensForUser,
  generateTokensFromRefreshToken,
} from './tokens.js'
import {
  setAuthCookies,
  clearAuthCookies,
  extractTokensFromRequest,
  calculateExpiration,
} from './cookies.js'

export const registerHandlers = (plugin: PluginAPI) => {
  const authGroup = plugin.addGroup('/auth')
  const settings = getSettings()

  authGroup.defineRoute({
    method: 'post',
    path: '/login',
    schema: (z) => ({
      body: z.object({
        username: z.string(),
        password: z.string(),
        client: z.string().optional(),
        aud: settings.aud?.required ? z.string() : z.string().optional(),
        mode: z.enum(['body', 'cookie']).optional(),
      }),
      response: z.object({
        userId: z.string(),
        accessToken: z.string(),
        refreshToken: z.string(),
        expiresIn: z.number(),
        expiresAt: z.string(),
      }),
    }),
    handler: async ({ req, res }) => {
      const { username, password, client, aud, mode } = req.body
      const ipAddress = getRequestIp(req)

      const user = await settings.dataProvider.findUserIdentifiers(username)

      if (!user) {
        if (settings.onLoginFailed) {
          await settings.onLoginFailed({
            username,
            errorType: 'invalid_username',
            client: client || '',
            ipAddress: ipAddress || '',
          })
        }
        return unauthorizedError('INVALID_LOGIN')
      }

      const isPasswordValid = await bcrypt.compare(password, user.passwordHash)

      if (!isPasswordValid) {
        if (settings.onLoginFailed) {
          await settings.onLoginFailed({
            username,
            errorType: 'invalid_password',
            client: client || '',
            ipAddress: ipAddress || '',
          })
        }
        return unauthorizedError('INVALID_LOGIN')
      }

      if (aud && typeof settings.aud?.isUserRoleAllowed === 'function') {
        const isAllowed = settings.aud.isUserRoleAllowed(user.role || '', aud)

        if (!isAllowed) {
          if (settings.onLoginFailed) {
            await settings.onLoginFailed({
              username,
              errorType: 'invalid_role',
              client: client || '',
              ipAddress: ipAddress || '',
            })
          }
          return unauthorizedError('INVALID_LOGIN')
        }
      }

      const { accessToken, refreshToken } = await generateTokensForUser({
        username,
        userId: user.userId,
        aud,
      })

      if (settings.onLoginSuccess) {
        await settings.onLoginSuccess({
          userId: user.userId,
          username,
          client: client || '',
          ipAddress: ipAddress || '',
        })
      }

      if (mode === 'cookie') {
        setAuthCookies(
          res,
          { accessToken, refreshToken },
          settings.accessTokenTTL
        )
      }

      const expiration = calculateExpiration(settings.accessTokenTTL)

      return {
        userId: user.userId,
        accessToken,
        refreshToken,
        ...expiration,
      }
    },
  })

  authGroup.defineRoute({
    method: 'post',
    path: '/refresh',
    schema: (z) => ({
      body: z
        .object({
          accessToken: z.string().optional(),
          refreshToken: z.string().optional(),
        })
        .optional(),
      response: z.object({
        userId: z.string(),
        accessToken: z.string(),
        refreshToken: z.string(),
        expiresIn: z.number(),
        expiresAt: z.string(),
      }),
    }),
    handler: async ({ req, res }) => {
      // Extract tokens from cookies or body (auto-detect)
      const extractedTokens = extractTokensFromRequest(req)

      if (!extractedTokens) {
        return unauthorizedError('NO_TOKENS_PROVIDED')
      }

      const { accessToken, refreshToken } = extractedTokens

      try {
        const tokens = await generateTokensFromRefreshToken({
          accessToken,
          refreshToken,
        })

        // Set cookies if the request came with cookies (auto-detect mode)
        const mode = req.cookies?.[
          settings.cookies?.refreshTokenName || 'dotpress_refresh_token'
        ]
          ? 'cookie'
          : 'body'

        if (mode === 'cookie') {
          setAuthCookies(
            res,
            {
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
            },
            settings.accessTokenTTL
          )
        }

        const expiration = calculateExpiration(settings.accessTokenTTL)

        return {
          userId: tokens.userId,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          ...expiration,
        }
      } catch (e) {
        const errorMessage = (e as Record<string, string>).message

        if (errorMessage === 'Invalid_Refresh_Token') {
          return unauthorizedError('INVALID_REFRESH_TOKEN')
        }
        if (errorMessage === 'Expired_Refresh_Token') {
          return unauthorizedError('EXPIRED_REFRESH_TOKEN')
        }

        return internalError('Can not refresh tokens.')
      }
    },
  })

  authGroup.defineRoute({
    method: 'get',
    path: '/me',
    handler: async ({ req }) => {
      if (!req.user) {
        return unauthorizedError()
      }

      return req.user
    },
  })

  authGroup.defineRoute({
    method: 'post',
    path: '/logout',
    handler: async ({ req, res }) => {
      const userId = ((req.user as Record<string, unknown>)?.id as string) || ''

      if (!userId) {
        return unauthorizedError()
      }

      await settings.dataProvider.revokeTokens(userId)
      clearAuthCookies(res)

      return { success: true }
    },
  })
}
