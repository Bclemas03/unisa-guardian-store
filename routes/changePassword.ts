/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Request, Response, NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')

/* DOESN'T REQUIRE typescript-dotnet-commonjs IMPORT BUT STILL REQUIRES MODULE
    RUN npm install typescript-dotnet-commonjs ON START AND YOU MAY ALSO HAVE TO
    INSTALL typescript-dotnet-commonjs LOCALLY ON THE COMPUTER RUNNING THE SERVER FIRST */

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

module.exports = function changePassword () {
  return ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current
    const newPassword = query.new
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat
    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
    /* ensure newPassword matches constraints
    const regex pattern to check for password strength
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/
    RegExp Code for 1 upper, lower, number & special character with min length 5 */
    // eslint-disable-next-line no-useless-escape
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/.test(JSON.stringify(newPassword))) {
      res.status(401).send(res.__('Ensure your new password has an uppercase, lowercase, number and symbol '))
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
    /* ensure newPassword matches constraints */
    } else {
      const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
      const loggedInUser = security.authenticatedUsers.get(token)
      if (loggedInUser) {
        if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
          res.status(401).send(res.__('Current password is not correct.'))
        } else {
          UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
            if (user) {
              user.update({ password: newPasswordInString }).then((user: UserModel) => {
                challengeUtils.solveIf(challenges.changePasswordBenderChallenge, () => { return user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic') })
                res.json({ user })
              }).catch((error: Error) => {
                next(error)
              })
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
      } else {
        next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      }
    }
  }
}
