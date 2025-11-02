import type { Request, Response, NextFunction } from 'express'
import { getSettings } from './settings.js'
import { validateAndDecodeAccessToken } from './tokens.js'
import { extractAccessToken } from './cookies.js'

export const attachAuthenticatedUser = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  const accessToken = extractAccessToken(req)

  if (!accessToken) {
    next()
    return
  }

  try {
    const settings = getSettings()
    const { userId } = validateAndDecodeAccessToken(accessToken)
    const user = await settings.dataProvider.findUserById(userId)
    if (user) {
      req.user = user
    }
    next()
  } catch (e) {
    console.warn(e)
    next()
  }
}
