import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { Request, Response } from 'express'
import {
  getCookieSettings,
  setAuthCookies,
  clearAuthCookies,
  detectAuthMode,
  extractTokensFromRequest,
  extractAccessToken,
  calculateExpiration,
} from '../../lib/cookies.js'
import { setSettings } from '../../lib/settings.js'
import type { DataProvider } from '../../types/types.js'

describe('Cookie Utilities', () => {
  beforeEach(() => {
    // Reset settings before each test
    setSettings({
      keys: {
        secretKey: 'test-secret',
        publicKey: 'test-public',
      },
      dataProvider: {
        storeRefreshToken: vi.fn(),
        findRefreshToken: vi.fn(),
        markRefreshTokenAsUsed: vi.fn(),
        revokeTokens: vi.fn(),
        findUserById: vi.fn(),
        findUserIdentifiers: vi.fn(),
      },
    })
  })

  describe('getCookieSettings', () => {
    it('should return default settings when no cookies config provided', () => {
      const settings = getCookieSettings()

      expect(settings).toMatchObject({
        enabled: false,
        httpOnly: true,
        secure: expect.any(Boolean),
        sameSite: 'lax',
        path: '/',
        accessTokenName: 'dotpress_access_token',
        refreshTokenName: 'dotpress_refresh_token',
        accessTokenInCookie: false,
      })
    })

    it('should merge custom settings with defaults', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          domain: '.example.com',
          accessTokenName: 'custom_access',
        },
      })

      const settings = getCookieSettings()

      expect(settings).toMatchObject({
        enabled: true,
        domain: '.example.com',
        accessTokenName: 'custom_access',
        refreshTokenName: 'dotpress_refresh_token', // Default
      })
    })
  })

  describe('setAuthCookies', () => {
    it('should not set cookies when cookies are disabled', () => {
      // Ensure cookies are disabled
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: false,
        },
      })

      const mockRes = {
        cookie: vi.fn(),
      } as unknown as Response

      setAuthCookies(
        mockRes,
        { accessToken: 'acc-token', refreshToken: 'ref-token' },
        3600
      )

      expect(mockRes.cookie).not.toHaveBeenCalled()
    })

    it('should set refresh token cookie when enabled', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
        },
      })

      const mockRes = {
        cookie: vi.fn(),
      } as unknown as Response

      setAuthCookies(
        mockRes,
        { accessToken: 'acc-token', refreshToken: 'ref-token' },
        3600
      )

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'dotpress_refresh_token',
        'ref-token',
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'lax',
          path: '/',
          maxAge: 3600000,
        })
      )

      // Access token should NOT be set by default
      expect(mockRes.cookie).toHaveBeenCalledTimes(1)
    })

    it('should set both cookies when accessTokenInCookie is true', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenInCookie: true,
        },
      })

      const mockRes = {
        cookie: vi.fn(),
      } as unknown as Response

      setAuthCookies(
        mockRes,
        { accessToken: 'acc-token', refreshToken: 'ref-token' },
        3600
      )

      expect(mockRes.cookie).toHaveBeenCalledTimes(2)
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'dotpress_access_token',
        'acc-token',
        expect.any(Object)
      )
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'dotpress_refresh_token',
        'ref-token',
        expect.any(Object)
      )
    })

    it('should use custom cookie names', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenName: 'my_access',
          refreshTokenName: 'my_refresh',
        },
      })

      const mockRes = {
        cookie: vi.fn(),
      } as unknown as Response

      setAuthCookies(
        mockRes,
        { accessToken: 'acc-token', refreshToken: 'ref-token' },
        3600
      )

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'my_refresh',
        'ref-token',
        expect.any(Object)
      )
    })

    it('should set domain when configured', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
          domain: '.example.com',
        },
      })

      const mockRes = {
        cookie: vi.fn(),
      } as unknown as Response

      setAuthCookies(
        mockRes,
        { accessToken: 'acc-token', refreshToken: 'ref-token' },
        3600
      )

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'dotpress_refresh_token',
        'ref-token',
        expect.objectContaining({
          domain: '.example.com',
        })
      )
    })
  })

  describe('clearAuthCookies', () => {
    it('should not clear cookies when disabled', () => {
      // Ensure cookies are disabled
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: false,
        },
      })

      const mockRes = {
        clearCookie: vi.fn(),
      } as unknown as Response

      clearAuthCookies(mockRes)

      expect(mockRes.clearCookie).not.toHaveBeenCalled()
    })

    it('should clear refresh token cookie when enabled', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
        },
      })

      const mockRes = {
        clearCookie: vi.fn(),
      } as unknown as Response

      clearAuthCookies(mockRes)

      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'dotpress_refresh_token',
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'lax',
          path: '/',
        })
      )
    })

    it('should clear both cookies when accessTokenInCookie is true', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          secure: false,
          accessTokenInCookie: true,
        },
      })

      const mockRes = {
        clearCookie: vi.fn(),
      } as unknown as Response

      clearAuthCookies(mockRes)

      expect(mockRes.clearCookie).toHaveBeenCalledTimes(2)
      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'dotpress_access_token',
        expect.any(Object)
      )
      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'dotpress_refresh_token',
        expect.any(Object)
      )
    })
  })

  describe('detectAuthMode', () => {
    it('should return "cookie" when refresh token cookie is present', () => {
      const mockReq = {
        cookies: {
          dotpress_refresh_token: 'ref-token',
        },
      } as unknown as Request

      const mode = detectAuthMode(mockReq)

      expect(mode).toBe('cookie')
    })

    it('should return "body" when refresh token is in body', () => {
      const mockReq = {
        cookies: {},
        body: {
          refreshToken: 'ref-token',
        },
      } as unknown as Request

      const mode = detectAuthMode(mockReq)

      expect(mode).toBe('body')
    })

    it('should prioritize cookies over body', () => {
      const mockReq = {
        cookies: {
          dotpress_refresh_token: 'cookie-ref-token',
        },
        body: {
          refreshToken: 'body-ref-token',
        },
      } as unknown as Request

      const mode = detectAuthMode(mockReq)

      expect(mode).toBe('cookie')
    })

    it('should return null when no tokens found', () => {
      const mockReq = {
        cookies: {},
        body: {},
      } as unknown as Request

      const mode = detectAuthMode(mockReq)

      expect(mode).toBeNull()
    })

    it('should work with custom cookie names', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          refreshTokenName: 'custom_refresh',
        },
      })

      const mockReq = {
        cookies: {
          custom_refresh: 'ref-token',
        },
      } as unknown as Request

      const mode = detectAuthMode(mockReq)

      expect(mode).toBe('cookie')
    })
  })

  describe('extractTokensFromRequest', () => {
    it('should extract tokens from cookies', () => {
      // Ensure cookies are enabled with default settings
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
        },
      })

      const mockReq = {
        cookies: {
          dotpress_refresh_token: 'ref-token',
        },
        body: {
          accessToken: 'acc-token-from-body',
        },
      } as unknown as Request

      const tokens = extractTokensFromRequest(mockReq)

      expect(tokens).toEqual({
        accessToken: 'acc-token-from-body',
        refreshToken: 'ref-token',
      })
    })

    it('should extract tokens from body when no cookies', () => {
      const mockReq = {
        cookies: {},
        body: {
          accessToken: 'acc-token',
          refreshToken: 'ref-token',
        },
      } as unknown as Request

      const tokens = extractTokensFromRequest(mockReq)

      expect(tokens).toEqual({
        accessToken: 'acc-token',
        refreshToken: 'ref-token',
      })
    })

    it('should extract both tokens from cookies when accessTokenInCookie is true', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          accessTokenInCookie: true,
        },
      })

      const mockReq = {
        cookies: {
          dotpress_access_token: 'acc-token-cookie',
          dotpress_refresh_token: 'ref-token-cookie',
        },
        body: {},
      } as unknown as Request

      const tokens = extractTokensFromRequest(mockReq)

      expect(tokens).toEqual({
        accessToken: 'acc-token-cookie',
        refreshToken: 'ref-token-cookie',
      })
    })

    it('should return null when tokens are missing', () => {
      const mockReq = {
        cookies: {
          dotpress_refresh_token: 'ref-token',
        },
        body: {},
      } as unknown as Request

      const tokens = extractTokensFromRequest(mockReq)

      expect(tokens).toBeNull()
    })
  })

  describe('extractAccessToken', () => {
    it('should prioritize Authorization header', () => {
      const mockReq = {
        headers: {
          authorization: 'Bearer header-token',
        },
        cookies: {
          dotpress_access_token: 'cookie-token',
        },
        body: {
          accessToken: 'body-token',
        },
      } as unknown as Request

      const token = extractAccessToken(mockReq)

      expect(token).toBe('header-token')
    })

    it('should extract from cookie when no header and accessTokenInCookie is true', () => {
      setSettings({
        keys: {
          secretKey: 'test-secret',
          publicKey: 'test-public',
        },
        dataProvider: {} as DataProvider,
        cookies: {
          enabled: true,
          accessTokenInCookie: true,
        },
      })

      const mockReq = {
        headers: {},
        cookies: {
          dotpress_access_token: 'cookie-token',
        },
        body: {
          accessToken: 'body-token',
        },
      } as unknown as Request

      const token = extractAccessToken(mockReq)

      expect(token).toBe('cookie-token')
    })

    it('should extract from body as fallback', () => {
      const mockReq = {
        headers: {},
        cookies: {},
        body: {
          accessToken: 'body-token',
        },
      } as unknown as Request

      const token = extractAccessToken(mockReq)

      expect(token).toBe('body-token')
    })

    it('should return null when no token found', () => {
      const mockReq = {
        headers: {},
        cookies: {},
        body: {},
      } as unknown as Request

      const token = extractAccessToken(mockReq)

      expect(token).toBeNull()
    })

    it('should handle Authorization header without Bearer prefix', () => {
      const mockReq = {
        headers: {
          authorization: 'invalid-format',
        },
        cookies: {},
        body: {},
      } as unknown as Request

      const token = extractAccessToken(mockReq)

      expect(token).toBeNull()
    })
  })

  describe('calculateExpiration', () => {
    it('should calculate correct expiration timestamp', () => {
      const expiresInSeconds = 3600
      const before = Date.now()

      const result = calculateExpiration(expiresInSeconds)

      const after = Date.now()

      expect(result.expiresIn).toBe(3600)
      expect(result.expiresAt).toBeDefined()

      const expiresAt = new Date(result.expiresAt).getTime()
      expect(expiresAt).toBeGreaterThanOrEqual(before + 3600 * 1000)
      expect(expiresAt).toBeLessThanOrEqual(after + 3600 * 1000)
    })

    it('should return ISO string format for expiresAt', () => {
      const result = calculateExpiration(1800)

      expect(result.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    })

    it('should handle different TTL values', () => {
      const result1 = calculateExpiration(60) // 1 minute
      const result2 = calculateExpiration(86400) // 1 day

      expect(result1.expiresIn).toBe(60)
      expect(result2.expiresIn).toBe(86400)

      const date1 = new Date(result1.expiresAt)
      const date2 = new Date(result2.expiresAt)

      expect(date2.getTime() - date1.getTime()).toBeGreaterThan(86000000) // Roughly 1 day
    })
  })
})
