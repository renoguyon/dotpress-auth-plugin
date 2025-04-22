import type { PluginAPI } from 'dotpress'
import { unauthorizedError, internalError } from 'dotpress'
import bcrypt from 'bcryptjs'
import { getSettings } from './settings.js'
import { getRequestIp } from './ip.js'
import {
  generateTokensForUser,
  generateTokensFromRefreshToken,
} from './tokens.js'

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
      }),
      response: z.object({
        userId: z.string(),
        accessToken: z.string(),
        refreshToken: z.string(),
      }),
    }),
    handler: async ({ req }) => {
      const { username, password, client } = req.body
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

      const { accessToken, refreshToken } = await generateTokensForUser({
        username,
        userId: user.userId,
      })

      if (settings.onLoginSuccess) {
        await settings.onLoginSuccess({
          userId: user.userId,
          username,
          client: client || '',
          ipAddress: ipAddress || '',
        })
      }

      return {
        userId: user.userId,
        accessToken,
        refreshToken,
      }
    },
  })

  authGroup.defineRoute({
    method: 'post',
    path: '/refresh',
    schema: (z) => ({
      body: z.object({
        accessToken: z.string(),
        refreshToken: z.string(),
      }),
      response: z.object({
        userId: z.string(),
        accessToken: z.string(),
        refreshToken: z.string(),
      }),
    }),
    handler: async ({ req }) => {
      const { accessToken, refreshToken } = req.body

      try {
        const tokens = await generateTokensFromRefreshToken({
          accessToken,
          refreshToken,
        })

        return {
          userId: tokens.userId,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
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
    handler: async ({ req }) => {
      const userId = ((req.user as Record<string, unknown>)?.id as string) || ''

      if (!userId) {
        return unauthorizedError()
      }

      await settings.dataProvider.revokeTokens(userId)

      return { success: true }
    },
  })
}
