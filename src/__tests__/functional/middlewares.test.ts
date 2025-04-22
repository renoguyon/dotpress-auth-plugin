import { describe, it, expect, beforeEach, vi } from 'vitest'
import request from 'supertest'
import { createApp, defineRoute } from 'dotpress'
import { DataProvider } from '../../types/types.js'
import * as tokenFns from '../../lib/tokens.js'
import { configurePlugin } from '../../index.js'

describe('Middlewares', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  const dataProvider: DataProvider = {
    storeRefreshToken: vi.fn(),
    findRefreshToken: vi.fn(),
    markRefreshTokenAsUsed: vi.fn(),
    revokeTokens: vi.fn(),
    findUserById: vi.fn(),
    findUserIdentifiers: vi.fn(),
  }

  const authPlugin = configurePlugin({
    keys: {
      secretKey: '',
      publicKey: '',
    },
    dataProvider,
  })

  it('should not attach a user if token not provided', async () => {
    defineRoute({
      path: '/test',
      handler: async ({ req }) => {
        return {
          status: 'ok',
          user: req.user,
        }
      },
    })

    const app = await createApp({
      plugins: [authPlugin],
    })

    const res = await request(app).get('/test')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      status: 'ok',
    })
  })

  it('should attach a user to request if authenticated', async () => {
    const decodeFn = vi
      .spyOn(tokenFns, 'validateAndDecodeAccessToken')
      .mockReturnValue({ userId: 'usr-123' })

    const findUserFn = vi.mocked(dataProvider.findUserById).mockResolvedValue({
      id: 'usr-123',
      username: 'JohnDoe111',
      email: 'JohnDoe111@example.com',
    })

    defineRoute({
      path: '/test',
      handler: async ({ req }) => {
        return {
          status: 'ok',
          user: req.user,
        }
      },
    })

    const app = await createApp({
      plugins: [authPlugin],
    })

    const res = await request(app)
      .get('/test')
      .set('Authorization', 'Bearer 1234567890')

    expect(decodeFn).toBeCalledWith('1234567890')
    expect(findUserFn).toBeCalledTimes(1)
    expect(findUserFn).toBeCalledWith('usr-123')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      status: 'ok',
      user: {
        id: 'usr-123',
        username: 'JohnDoe111',
        email: 'JohnDoe111@example.com',
      },
    })
  })

  it('should not attach a user if token is valid but user provider returns nothing', async () => {
    const decodeFn = vi
      .spyOn(tokenFns, 'validateAndDecodeAccessToken')
      .mockReturnValue({ userId: 'usr-123' })

    const findUserFn = vi
      .mocked(dataProvider.findUserById)
      .mockResolvedValue(undefined)

    defineRoute({
      path: '/test',
      handler: async ({ req }) => {
        return {
          status: 'ok',
          user: req.user,
        }
      },
    })

    const app = await createApp({
      plugins: [authPlugin],
    })

    const res = await request(app)
      .get('/test')
      .set('Authorization', 'Bearer 1234567890')

    expect(decodeFn).toBeCalledWith('1234567890')
    expect(findUserFn).toBeCalledTimes(1)
    expect(findUserFn).toBeCalledWith('usr-123')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      status: 'ok',
    })
  })
})
