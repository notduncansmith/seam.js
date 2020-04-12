import { Buffer } from 'buffer/'
import { secretbox, randomBytes } from 'tweetnacl'

export class SharedMessage {
  public body: Buffer
  public nonce: Buffer
  public mode = 'shared'

  constructor(public timestamp = new Date(), public destination = '') {}

  canonical(): Buffer {
    const str = [
      `{`,
      `"mode":"shared",`,
      `"body":"${this.body.toString('base64')}",`,
      `"destination":"${this.destination}",`,
      `"nonce":"${this.nonce.toString('base64')}",`,
      `"timestamp":${this.timestamp.valueOf()}`,
      `}`,
    ].join('')
    return Buffer.from(str)
  }

  writeBody(body: Buffer, secret: Buffer) {
    this.nonce = Buffer.from(randomBytes(secretbox.nonceLength))
    this.body = Buffer.from(secretbox(body, this.nonce, secret))
  }

  open(secret: Uint8Array): Buffer {
    return Buffer.from(secretbox.open(this.body, this.nonce, secret))
  }

  static parse(str: string): SharedMessage {
    const dm = new SharedMessage()
    const parsed = JSON.parse(str)
    dm.timestamp = parsed.timestamp
    dm.destination = parsed.destination
    dm.body = Buffer.from(parsed.body, 'base64')
    dm.nonce = Buffer.from(parsed.nonce, 'base64')
    return dm
  }
}
