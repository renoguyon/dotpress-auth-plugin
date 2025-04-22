import { PluginSettings } from '../types/types.js'

let pluginSettings: PluginSettings = {
  accessTokenTTL: 3600,
  refreshTokenTTLInDays: 14,
  issuer: '',
  keys: {
    secretKey: '',
    publicKey: '',
  },
  dataProvider: {
    storeRefreshToken: () => {
      throw new Error('storeRefreshToken() is not implemented.')
    },
    findRefreshToken: () => {
      throw new Error('findRefreshToken() is not implemented.')
    },
    markRefreshTokenAsUsed: () => {
      throw new Error('markRefreshTokenAsUsed() is not implemented.')
    },
    revokeTokens: () => {
      throw new Error('revokeTokens() is not implemented.')
    },
    findUserById: () => {
      throw new Error('findUserById() is not implemented.')
    },
    findUserIdentifiers: () => {
      throw new Error('findUserByUsername() is not implemented.')
    },
  },
  onLoginFailed: () => {
    return Promise.resolve()
  },
  onLoginSuccess: () => {
    return Promise.resolve()
  },
}

export const setSettings = (settings: Partial<PluginSettings>) => {
  pluginSettings = {
    ...pluginSettings,
    ...settings,
  }
}

export const getSettings = () => pluginSettings
