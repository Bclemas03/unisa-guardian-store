/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 */

import config = require('config')
import { Request, Response, NextFunction } from 'express'
import { Memory } from '../data/types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')

/* DOESN'T REQUIRE typescript-dotnet-commonjs IMPORT BUT STILL REQUIRES MODULE
    RUN npm install typescript-dotnet-commonjs ON START AND YOU MAY ALSO HAVE TO
    INSTALL typescript-dotnet-commonjs LOCALLY ON THE COMPUTER RUNNING THE SERVER FIRST */

const challenges = require('../data/datacache').challenges
const users = require('../data/datacache').users
const security = require('../lib/insecurity')

module.exports = function resetPassword () {
  return ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat

    if (!email || !answer) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
    } else if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
    /* ensure newPassword matches constraints
    const regex pattern to check for password strength
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/
    RegExp Code for 1 upper, lower, number & special character with min length 5 */
    // eslint-disable-next-line no-useless-escape
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/.test(JSON.stringify(newPassword))) {
      res.status(401).send(res.__('Ensure your new password has uppercase, and lowercase letters, as well as, numbers and symbols.'))
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
    } else {
      SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      }).then((data: SecurityAnswerModel | null) => {
        if (data && security.hmac(answer) === data.answer) {
          UserModel.findByPk(data.UserId).then((user: UserModel | null) => {
            user?.update({ password: newPassword }).then((user: UserModel) => {
              verifySecurityAnswerChallenges(user, answer)
              res.json({ user })
            }).catch((error: unknown) => {
              next(error)
            })
          }).catch((error: unknown) => {
            next(error)
          })
        } else {
          res.status(401).send(res.__('Wrong answer to security question.'))
        }
      }).catch((error: unknown) => {
        next(error)
      })
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories: Memory[] = config.get('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories: Memory[] = config.get('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
