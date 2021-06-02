import * as express from 'express'

declare namespace PasswordlessStrategy {
  interface StrategyStatic {
    new (options: StrategyOptions, verify: StrategyVerify): StrategyInstance
  }

  interface StrategyInstance {
    name: string
    authenticate: (req: express.Request, options?: any) => void
  }

  interface StrategyOptions {
    dynamicConfig: StrategyOptions
    access?: (user: string, callback: () => void) => void
  }

  type StrategyVerify = (
    req: Express.Request,
    email: string,
    done: (error: string, user?: any, info?: { [key: string]: any }) => void
  ) => void
}

declare const PasswordlessStrategy: PasswordlessStrategy.StrategyStatic
export = PasswordlessStrategy
