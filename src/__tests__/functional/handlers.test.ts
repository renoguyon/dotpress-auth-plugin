import { describe, it, expect, beforeEach, vi } from 'vitest'
import request from 'supertest'
import bcrypt from 'bcryptjs'
import { $clearRoutes, createApp } from 'dotpress'
import { DataProvider } from '../../types/types.js'
import * as tokenFns from '../../lib/tokens.js'
import { configurePlugin } from '../../index.js'

describe('Handlers', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    $clearRoutes()
  })

  const dataProvider: DataProvider = {
    storeRefreshToken: vi.fn(),
    findRefreshToken: vi.fn(),
    markRefreshTokenAsUsed: vi.fn(),
    revokeTokens: vi.fn(),
    findUserById: vi.fn(),
    findUserIdentifiers: vi.fn(),
  }

  const onLoginFailedCallback = vi.fn()
  const onLoginSuccessCallback = vi.fn()

  const authPlugin = configurePlugin({
    keys: {
      secretKey: '',
      publicKey: '',
    },
    dataProvider,
    onLoginFailed: onLoginFailedCallback,
    onLoginSuccess: onLoginSuccessCallback,
  })

  describe('Login Route', () => {
    it('should return 401 if user not found', async () => {
      const findUserIdentifiersFn = vi
        .mocked(dataProvider.findUserIdentifiers)
        .mockResolvedValue(undefined)

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
        client: 'User-Agent String',
      })

      expect(res.status).toBe(401)
      expect(findUserIdentifiersFn).toHaveBeenCalledTimes(1)
      expect(findUserIdentifiersFn).toHaveBeenCalledWith('JaneDoe')
      expect(onLoginFailedCallback).toHaveBeenCalledTimes(1)
      expect(onLoginFailedCallback).toHaveBeenCalledWith({
        username: 'JaneDoe',
        errorType: 'invalid_username',
        client: 'User-Agent String',
        ipAddress: '',
      })
    })

    it('should return 401 if user password mismatches', async () => {
      const findUserIdentifiersFn = vi
        .mocked(dataProvider.findUserIdentifiers)
        .mockResolvedValue({
          userId: '101',
          passwordHash: '',
        })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
      })

      expect(res.status).toBe(401)
      expect(findUserIdentifiersFn).toHaveBeenCalledTimes(1)
      expect(findUserIdentifiersFn).toHaveBeenCalledWith('JaneDoe')
      expect(onLoginFailedCallback).toHaveBeenCalledTimes(1)
      expect(onLoginFailedCallback).toHaveBeenCalledWith({
        username: 'JaneDoe',
        errorType: 'invalid_password',
        client: '',
        ipAddress: '',
      })
    })

    it('should return tokens if password is correct', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      const findUserIdentifiersFn = vi
        .mocked(dataProvider.findUserIdentifiers)
        .mockResolvedValue({
          userId: '101',
          passwordHash: pwdHash,
        })

      vi.spyOn(tokenFns, 'generateTokensForUser').mockResolvedValue({
        accessToken: 'acc-111222333',
        refreshToken: 'ref-999888777',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
      })

      expect(res.status).toBe(200)
      expect(findUserIdentifiersFn).toHaveBeenCalledTimes(1)
      expect(findUserIdentifiersFn).toHaveBeenCalledWith('JaneDoe')
      expect(onLoginSuccessCallback).toHaveBeenCalledTimes(1)
      expect(onLoginSuccessCallback).toHaveBeenCalledWith({
        userId: '101',
        username: 'JaneDoe',
        client: '',
        ipAddress: '',
      })
      expect(res.body).toEqual({
        userId: '101',
        accessToken: 'acc-111222333',
        refreshToken: 'ref-999888777',
      })
    })
  })

  describe('Refresh Token Route', () => {
    it('should return 401 if refresh token is invalid', async () => {
      const generateTokenFn = vi
        .spyOn(tokenFns, 'generateTokensFromRefreshToken')
        .mockImplementation(() => {
          throw new Error('Invalid_Refresh_Token')
        })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/refresh').send({
        accessToken: '123456789',
        refreshToken: '000000000',
      })

      expect(res.status).toBe(401)
      expect(res.body).toEqual({
        status: 401,
        error: 'UNAUTHORIZED',
        message: 'INVALID_REFRESH_TOKEN',
      })
      expect(generateTokenFn).toHaveBeenCalledTimes(1)
      expect(generateTokenFn).toHaveBeenCalledWith({
        accessToken: '123456789',
        refreshToken: '000000000',
      })
    })

    it('should return 200 OK and new tokens if refresh token is valid', async () => {
      const generateTokenFn = vi
        .spyOn(tokenFns, 'generateTokensFromRefreshToken')
        .mockResolvedValue({
          userId: '102',
          accessToken: '111222333',
          refreshToken: '111111111',
        })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/refresh').send({
        accessToken: '123456789',
        refreshToken: '000000000',
      })

      expect(res.status).toBe(200)
      expect(res.body).toEqual({
        userId: '102',
        accessToken: '111222333',
        refreshToken: '111111111',
      })
      expect(generateTokenFn).toHaveBeenCalledTimes(1)
      expect(generateTokenFn).toHaveBeenCalledWith({
        accessToken: '123456789',
        refreshToken: '000000000',
      })
    })
  })

  describe('Current User Route', () => {
    it('should return 401 if no current user', async () => {
      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).get('/auth/me')

      expect(res.status).toBe(401)
    })

    it('should load current user', async () => {
      const findUserFn = vi
        .mocked(dataProvider.findUserById)
        .mockResolvedValue({
          id: 'usr-123',
          username: 'JohnDoe111',
          email: 'JohnDoe111@example.com',
        })

      const decodeFn = vi
        .spyOn(tokenFns, 'validateAndDecodeAccessToken')
        .mockReturnValue({ userId: 'usr-123' })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app)
        .get('/auth/me')
        .set('Authorization', 'Bearer 0123456789')

      expect(decodeFn).toBeCalledWith('0123456789')
      expect(findUserFn).toBeCalledTimes(1)
      expect(findUserFn).toBeCalledWith('usr-123')
      expect(res.status).toBe(200)
      expect(res.body).toEqual({
        id: 'usr-123',
        username: 'JohnDoe111',
        email: 'JohnDoe111@example.com',
      })
    })
  })

  describe('Logout Route', () => {
    it('should return 401 if no current user', async () => {
      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/logout')

      expect(res.status).toBe(401)
    })

    it('should revoke token and return 200 OK', async () => {
      vi.mocked(dataProvider.findUserById).mockResolvedValue({
        id: 'usr-123',
        username: 'JohnDoe111',
        email: 'JohnDoe111@example.com',
      })

      vi.spyOn(tokenFns, 'validateAndDecodeAccessToken').mockReturnValue({
        userId: 'usr-123',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app)
        .post('/auth/logout')
        .set('Authorization', 'Bearer 0123456789')

      expect(vi.mocked(dataProvider.revokeTokens)).toBeCalledTimes(1)
      expect(vi.mocked(dataProvider.revokeTokens)).toBeCalledWith('usr-123')
      expect(res.status).toBe(200)
      expect(res.body).toEqual({ success: true })
    })
  })
})
