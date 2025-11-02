import { describe, it, expect, beforeEach, vi } from 'vitest'
import request from 'supertest'
import bcrypt from 'bcryptjs'
import { $clearRoutes, createApp } from 'dotpress'
import { DataProvider } from '../../types/types.js'
import * as tokenFns from '../../lib/tokens.js'
import { configurePlugin } from '../../index.js'

describe('Cookie Mode Authentication', () => {
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

  const authPlugin = configurePlugin({
    keys: {
      secretKey: '',
      publicKey: '',
    },
    dataProvider,
    cookies: {
      enabled: true,
      secure: false, // For testing
      httpOnly: true,
      sameSite: 'lax',
    },
  })

  describe('POST /auth/login with cookie mode', () => {
    it('should set cookies when mode is "cookie"', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
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
        mode: 'cookie',
      })

      expect(res.status).toBe(200)

      // Check response body
      expect(res.body).toMatchObject({
        userId: '101',
        accessToken: 'acc-111222333',
        refreshToken: 'ref-999888777',
        expiresIn: expect.any(Number),
        expiresAt: expect.any(String),
      })

      // Check cookies are set
      expect(res.headers['set-cookie']).toBeDefined()
      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]

      // Check refresh token cookie
      const refreshCookie = cookies.find((c) =>
        c.startsWith('dotpress_refresh_token=')
      )
      expect(refreshCookie).toBeDefined()
      expect(refreshCookie).toContain('HttpOnly')
      expect(refreshCookie).toContain('Path=/')
      expect(refreshCookie).toContain('SameSite=Lax')

      // Access token should NOT be in cookie by default
      const accessCookie = cookies.find((c) =>
        c.startsWith('dotpress_access_token=')
      )
      expect(accessCookie).toBeUndefined()
    })

    it('should set access token cookie when accessTokenInCookie is true', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
        userId: '101',
        passwordHash: pwdHash,
      })

      vi.spyOn(tokenFns, 'generateTokensForUser').mockResolvedValue({
        accessToken: 'acc-111222333',
        refreshToken: 'ref-999888777',
      })

      const authPluginWithAccessCookie = configurePlugin({
        keys: {
          secretKey: '',
          publicKey: '',
        },
        dataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenInCookie: true, // Enable access token in cookie
        },
      })

      const app = await createApp({
        plugins: [authPluginWithAccessCookie],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
        mode: 'cookie',
      })

      expect(res.status).toBe(200)

      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]

      // Both tokens should be in cookies
      const refreshCookie = cookies.find((c) =>
        c.startsWith('dotpress_refresh_token=')
      )
      const accessCookie = cookies.find((c) =>
        c.startsWith('dotpress_access_token=')
      )

      expect(refreshCookie).toBeDefined()
      expect(accessCookie).toBeDefined()
    })

    it('should NOT set cookies when mode is "body"', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
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
        mode: 'body',
      })

      expect(res.status).toBe(200)
      expect(res.body.accessToken).toBe('acc-111222333')

      // No cookies should be set
      expect(res.headers['set-cookie']).toBeUndefined()
    })

    it('should NOT set cookies when mode is not specified (default)', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
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

      // No cookies should be set (backward compatibility)
      expect(res.headers['set-cookie']).toBeUndefined()
    })
  })

  describe('POST /auth/refresh with cookies', () => {
    it('should refresh tokens using cookies', async () => {
      vi.spyOn(tokenFns, 'generateTokensFromRefreshToken').mockResolvedValue({
        userId: '102',
        accessToken: 'new-acc-token',
        refreshToken: 'new-ref-token',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      // Simulate request with cookies
      const res = await request(app)
        .post('/auth/refresh')
        .set('Cookie', [
          'dotpress_refresh_token=ref-999888777',
          'dotpress_access_token=acc-111222333',
        ])
        .send({})

      expect(res.status).toBe(200)
      expect(res.body).toMatchObject({
        userId: '102',
        accessToken: 'new-acc-token',
        refreshToken: 'new-ref-token',
        expiresIn: expect.any(Number),
        expiresAt: expect.any(String),
      })

      // New cookies should be set
      expect(res.headers['set-cookie']).toBeDefined()
      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]
      expect(cookies.some((c) => c.includes('new-ref-token'))).toBe(true)
    })

    it('should fallback to body mode when no cookies present', async () => {
      vi.spyOn(tokenFns, 'generateTokensFromRefreshToken').mockResolvedValue({
        userId: '102',
        accessToken: 'new-acc-token',
        refreshToken: 'new-ref-token',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/refresh').send({
        accessToken: 'acc-111222333',
        refreshToken: 'ref-999888777',
      })

      expect(res.status).toBe(200)
      expect(res.body.accessToken).toBe('new-acc-token')

      // No cookies should be set in body mode
      expect(res.headers['set-cookie']).toBeUndefined()
    })

    it('should return 401 when no tokens provided', async () => {
      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app).post('/auth/refresh').send({})

      expect(res.status).toBe(401)
      expect(res.body.error).toBe('UNAUTHORIZED')
      expect(res.body.message).toBe('NO_TOKENS_PROVIDED')
    })
  })

  describe('POST /auth/logout with cookies', () => {
    it('should clear cookies on logout', async () => {
      vi.mocked(dataProvider.findUserById).mockResolvedValue({
        id: 'usr-123',
        username: 'JohnDoe',
        email: 'john@example.com',
      })

      vi.spyOn(tokenFns, 'validateAndDecodeAccessToken').mockReturnValue({
        userId: 'usr-123',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app)
        .post('/auth/logout')
        .set('Authorization', 'Bearer valid-token')
        .set('Cookie', ['dotpress_refresh_token=ref-token'])

      expect(res.status).toBe(200)
      expect(res.body).toEqual({ success: true })

      // Cookies should be cleared
      expect(res.headers['set-cookie']).toBeDefined()
      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]

      // Check that cookies are being cleared (Max-Age=0 or Expires in the past)
      const refreshCookie = cookies.find((c) =>
        c.startsWith('dotpress_refresh_token=')
      )
      expect(refreshCookie).toBeDefined()
      // Cookie should have an expiry in the past or Max-Age=0
      expect(
        refreshCookie!.includes('Max-Age=0') ||
          refreshCookie!.includes('Expires=Thu, 01 Jan 1970')
      ).toBe(true)
    })
  })

  describe('GET /auth/me with cookies', () => {
    it('should authenticate user with access token from Authorization header', async () => {
      vi.mocked(dataProvider.findUserById).mockResolvedValue({
        id: 'usr-123',
        username: 'JohnDoe',
        email: 'john@example.com',
      })

      vi.spyOn(tokenFns, 'validateAndDecodeAccessToken').mockReturnValue({
        userId: 'usr-123',
      })

      const app = await createApp({
        plugins: [authPlugin],
      })

      const res = await request(app)
        .get('/auth/me')
        .set('Authorization', 'Bearer valid-token')

      expect(res.status).toBe(200)
      expect(res.body).toEqual({
        id: 'usr-123',
        username: 'JohnDoe',
        email: 'john@example.com',
      })
    })

    it('should authenticate user with access token from cookie when accessTokenInCookie is true', async () => {
      vi.mocked(dataProvider.findUserById).mockResolvedValue({
        id: 'usr-456',
        username: 'JaneDoe',
        email: 'jane@example.com',
      })

      vi.spyOn(tokenFns, 'validateAndDecodeAccessToken').mockReturnValue({
        userId: 'usr-456',
      })

      const authPluginWithAccessCookie = configurePlugin({
        keys: {
          secretKey: '',
          publicKey: '',
        },
        dataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenInCookie: true,
        },
      })

      const app = await createApp({
        plugins: [authPluginWithAccessCookie],
      })

      const res = await request(app)
        .get('/auth/me')
        .set('Cookie', ['dotpress_access_token=cookie-token'])

      expect(res.status).toBe(200)
      expect(res.body.username).toBe('JaneDoe')
    })
  })

  describe('Custom cookie names', () => {
    it('should use custom cookie names when configured', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
        userId: '101',
        passwordHash: pwdHash,
      })

      vi.spyOn(tokenFns, 'generateTokensForUser').mockResolvedValue({
        accessToken: 'acc-token',
        refreshToken: 'ref-token',
      })

      const customAuthPlugin = configurePlugin({
        keys: {
          secretKey: '',
          publicKey: '',
        },
        dataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenName: 'custom_access',
          refreshTokenName: 'custom_refresh',
        },
      })

      const app = await createApp({
        plugins: [customAuthPlugin],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
        mode: 'cookie',
      })

      expect(res.status).toBe(200)

      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]
      expect(cookies.some((c) => c.startsWith('custom_refresh='))).toBe(true)
    })
  })

  describe('Cross-domain cookie configuration', () => {
    it('should set domain attribute when configured', async () => {
      const pwdHash = await bcrypt.hash('123456', 10)

      vi.mocked(dataProvider.findUserIdentifiers).mockResolvedValue({
        userId: '101',
        passwordHash: pwdHash,
      })

      vi.spyOn(tokenFns, 'generateTokensForUser').mockResolvedValue({
        accessToken: 'acc-token',
        refreshToken: 'ref-token',
      })

      const domainAuthPlugin = configurePlugin({
        keys: {
          secretKey: '',
          publicKey: '',
        },
        dataProvider,
        cookies: {
          enabled: true,
          secure: false,
          domain: '.example.com',
        },
      })

      const app = await createApp({
        plugins: [domainAuthPlugin],
      })

      const res = await request(app).post('/auth/login').send({
        username: 'JaneDoe',
        password: '123456',
        mode: 'cookie',
      })

      expect(res.status).toBe(200)

      const cookies = Array.isArray(res.headers['set-cookie'])
        ? res.headers['set-cookie']
        : [res.headers['set-cookie'] as string]
      const refreshCookie = cookies.find((c) =>
        c.startsWith('dotpress_refresh_token=')
      )

      expect(refreshCookie).toContain('Domain=.example.com')
    })
  })
})
