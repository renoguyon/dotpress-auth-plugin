import type { Request } from 'express'
import requestIp from 'request-ip'

export const getRequestIp = (req: Request): string | null => {
  const clientIp: string | null = requestIp.getClientIp(req)

  const localIps = [
    '127.0.0.1',
    'localhost',
    '::1',
    '::ffff',
    '::ffff:127.0.0.1',
  ]

  if (clientIp && localIps.includes(clientIp)) {
    return null
  }

  return clientIp
}
