import type { Plugin } from 'dotpress'
import { AuthSettings, DataProvider, KeyPairSettings } from './types/types.js'
import { setSettings } from './lib/settings.js'
import { registerHandlers } from './lib/handlers.js'
import { attachAuthenticatedUser } from './lib/middleware.js'
import bcrypt from 'bcryptjs'

type Settings = Partial<AuthSettings> & {
  keys: KeyPairSettings
  dataProvider: DataProvider
}

export const configurePlugin = (settings: Settings): Plugin => {
  setSettings(settings)

  return (plugin) => {
    plugin.useBeforeRoutes((app) => {
      app.use(attachAuthenticatedUser)
    })

    registerHandlers(plugin)
  }
}

export const generatePasswordHash = (
  password: string,
  salt = 10
): Promise<string> => {
  return bcrypt.hash(password, salt)
}
