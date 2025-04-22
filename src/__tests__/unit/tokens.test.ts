import {
  describe,
  it,
  expect,
  beforeEach,
  vi,
  beforeAll,
  afterEach,
} from 'vitest'
import jwt from 'jsonwebtoken'
import { setSettings } from '../../lib/settings.js'
import * as tokenFns from '../../lib/tokens.js'
import * as generators from '../../lib/generators.js'
import { DataProvider } from '../../types/types.js'

describe('Tokens', () => {
  const dataProvider: DataProvider = {
    storeRefreshToken: vi.fn(),
    findRefreshToken: vi.fn(),
    markRefreshTokenAsUsed: vi.fn(),
    revokeTokens: vi.fn(),
    findUserById: vi.fn(),
    findUserIdentifiers: vi.fn(),
  }

  beforeAll(() => {
    setSettings({
      keys: {
        secretKey: 'secret_111222',
        publicKey: 'public_111222',
      },
      issuer: 'auth.myapp.com',
      accessTokenTTL: 3600,
      dataProvider,
    })
  })

  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2025-01-01T00:00:00Z'))
    vi.spyOn(generators, 'generateUUID').mockReturnValue('000-000-000-000-000')
  })

  afterEach(() => {
    vi.resetAllMocks()
    vi.useRealTimers()
  })

  describe('Function: createAccessTokenFromPayload()', () => {
    it('should generate token and return expected data', () => {
      // @ts-expect-error issues with jsonwebtoken types
      const jwtSignFn = vi.spyOn(jwt, 'sign').mockReturnValue('acc-1111111111')

      const output = tokenFns.createAccessTokenFromPayload({
        sub: '101',
        username: 'JaneDoe',
        auth_time: 1735689600000,
      })

      expect(jwtSignFn).toHaveBeenCalledTimes(1)

      expect(jwtSignFn).toHaveBeenCalledWith(
        {
          sub: '101',
          username: 'JaneDoe',
          auth_time: 1735689600000,
        },
        'secret_111222',
        {
          algorithm: 'RS256',
          issuer: 'auth.myapp.com',
          expiresIn: 3600,
          jwtid: '000-000-000-000-000',
        }
      )

      expect(output).toEqual({
        jwtId: '000-000-000-000-000',
        accessToken: 'acc-1111111111',
      })
    })
  })

  describe('Function: generateRefreshToken()', () => {
    it('should return token and hashed token', () => {
      const output = tokenFns.generateRefreshToken()

      expect(output).toEqual({
        token: expect.any(String),
        tokenHash: expect.any(String),
      })
    })
  })

  describe('Function: generateTokensForUser()', () => {
    it('should generate tokens and return expected data', async () => {
      const storeRefreshTokenFn = vi
        .mocked(dataProvider.storeRefreshToken)
        .mockResolvedValue()

      // @ts-expect-error issues with jsonwebtoken types
      vi.spyOn(jwt, 'sign').mockReturnValue('acc-1111111111')

      const output = await tokenFns.generateTokensForUser({
        userId: '110',
        username: 'JaneDoe',
      })

      expect(storeRefreshTokenFn).toHaveBeenCalledTimes(1)
      expect(storeRefreshTokenFn).toHaveBeenCalledWith({
        token: expect.any(String),
        tokenHash: expect.any(String),
        userId: '110',
        jwtId: '000-000-000-000-000',
        expiresAt: new Date('2025-01-15T00:00:00.000Z'),
      })
      expect(output).toEqual({
        accessToken: 'acc-1111111111',
        refreshToken: expect.any(String),
      })
    })
  })

  describe('Function: generateTokensFromRefreshToken()', () => {
    beforeEach(() => {
      // @ts-expect-error issues with jsonwebtoken types
      vi.spyOn(jwt, 'verify').mockReturnValue({
        sub: '110',
        jti: 'jwt900',
      })
    })

    it('should throw error if token not found', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue(undefined)

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Invalid_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should throw error if token is revoked found', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '110',
          jwtId: 'jwt900',
          expiresAt: new Date('2025-01-15T00:00:00.000Z'),
          isUsed: false,
          revokedAt: new Date(),
        })

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Invalid_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should throw error if token is used', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '110',
          jwtId: 'jwt900',
          expiresAt: new Date('2025-01-15T00:00:00.000Z'),
          isUsed: true,
          revokedAt: null,
        })

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Invalid_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should throw error if userId mismatches', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '200',
          jwtId: 'jwt900',
          expiresAt: new Date('2025-01-15T00:00:00.000Z'),
          isUsed: false,
          revokedAt: null,
        })

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Invalid_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should throw error if jwtid mismatches', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '110',
          jwtId: 'jwt100',
          expiresAt: new Date('2025-01-15T00:00:00.000Z'),
          isUsed: false,
          revokedAt: null,
        })

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Invalid_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should throw error if refresh token is expired', async () => {
      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '110',
          jwtId: 'jwt900',
          expiresAt: new Date('2024-12-31T00:00:00.000Z'),
          isUsed: false,
          revokedAt: null,
        })

      await expect(
        tokenFns.generateTokensFromRefreshToken({
          accessToken: 'acc100',
          refreshToken: 'refr100',
        })
      ).rejects.toThrow('Expired_Refresh_Token')

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
    })

    it('should generate new tokens if refresh token is valid', async () => {
      // @ts-expect-error issues with jsonwebtoken types
      vi.spyOn(jwt, 'sign').mockReturnValue('acc-1111111111')

      const findRefreshTokenSpy = vi
        .spyOn(dataProvider, 'findRefreshToken')
        .mockResolvedValue({
          userId: '110',
          jwtId: 'jwt900',
          expiresAt: new Date('2025-01-15T00:00:00.000Z'),
          isUsed: false,
          revokedAt: null,
        })

      const storeRefreshTokenFn = vi
        .mocked(dataProvider.storeRefreshToken)
        .mockResolvedValue()

      const markRefreshTokenAsUsedFn = vi
        .mocked(dataProvider.markRefreshTokenAsUsed)
        .mockResolvedValue()

      const output = await tokenFns.generateTokensFromRefreshToken({
        accessToken: 'acc100',
        refreshToken: 'refr100',
      })

      expect(findRefreshTokenSpy).toHaveBeenCalledTimes(1)
      expect(storeRefreshTokenFn).toHaveBeenCalledTimes(1)
      expect(markRefreshTokenAsUsedFn).toHaveBeenCalledTimes(1)
      expect(output).toEqual({
        userId: '110',
        accessToken: 'acc-1111111111',
        refreshToken: expect.any(String),
      })
    })
  })
})
