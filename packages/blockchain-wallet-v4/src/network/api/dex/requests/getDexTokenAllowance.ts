import type { RequestConfig } from '../../http'
import { DEX_NABU_GATEWAY_PREFIX } from '../constants'
import { DexTokenAllowanceSchema } from '../schemas'
import type { DexTokenAllowance } from '../types'

type Data = {
  addressOwner: string
  currency: string
  network: string
  spender: string
}

export const getDexTokenAllowance =
  ({ apiUrl, post }: { apiUrl: string; post: (config: RequestConfig) => Promise<unknown> }) =>
  (data: Data): Promise<DexTokenAllowance> =>
    post({
      contentType: 'application/json',
      data,
      endPoint: `/currency/evm/allowance`,
      removeDefaultPostData: true,
      // url: apiUrl
      url: 'https://api.blockchain.info'
    }).then((data) => {
      try {
        return DexTokenAllowanceSchema.parse(data)
      } catch (e) {
        console.error(e)
        throw e
      }
    })
