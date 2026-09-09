/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import { URL } from 'node:url'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isSafeUrl (urlString: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  let hostname = parsed.hostname.toLowerCase()
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1)
  }

  if (!hostname) {
    return false
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan')
  ) {
    return false
  }

  const ipType = net.isIP(hostname)
  if (ipType === 4) {
    const parts = hostname.split('.').map(Number)
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return false
    }
    if (parts[0] === 0) return false
    if (parts[0] === 10) return false
    if (parts[0] === 127) return false
    if (parts[0] === 169 && parts[1] === 254) return false
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
    if (parts[0] === 192 && parts[1] === 168) return false
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return false
    if (parts[0] >= 224) return false
  } else if (ipType === 6) {
    const lower = hostname.toLowerCase()
    if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
      return false
    }
    if (/^fe[89ab]/i.test(lower)) return false
    if (/^f[cd]/i.test(lower)) return false
    if (lower.startsWith('::ffff:')) {
      const v4Part = lower.slice(7)
      if (net.isIP(v4Part) === 4) {
        const parts = v4Part.split('.').map(Number)
        if (
          parts[0] === 0 ||
          parts[0] === 10 ||
          parts[0] === 127 ||
          (parts[0] === 169 && parts[1] === 254) ||
          (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
          (parts[0] === 192 && parts[1] === 168) ||
          (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
          parts[0] >= 224
        ) {
          return false
        }
      } else {
        return false
      }
    }
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url !== 'string' || !isSafeUrl(url)) {
          res.status(400)
          next(new Error('Invalid image URL'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
