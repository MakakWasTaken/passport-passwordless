import * as express from 'express'

declare namespace PasswordlessToken {
  interface StrategyStatic {
    new (options: StrategyOptions, verify: StrategyVerify): StrategyInstance
  }

  interface StrategyInstance {
    name: string
    authenticate: (
      req: express.Request,
      options?: Partial<StrategyOptions>
    ) => void
  }

  interface StrategyOptions {
    dynamicConfig?: StrategyOptions
    store: any
    userField?: string
    tokenField?: string
    uidField?: string
    delivery: (
      tokenToSend: string,
      uidToSend: string,
      recipient: string,
      callback: any,
      req: Express.Request
    ) => {}
    allowTokenReuse: boolean
    tokenLifeTime: number
    access?: (user: string, callback: () => void) => void
  }

  type StrategyVerify = (
    req: express.Request,
    email: string,
    done: (error: Error, user?: any, info?: { [key: string]: any }) => void
  ) => void
}

declare const PasswordlessToken: PasswordlessToken.StrategyStatic
export = PasswordlessToken
