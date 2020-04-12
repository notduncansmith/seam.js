import { Buffer } from 'buffer/'
import { box, randomBytes } from 'tweetnacl'

export class DirectMessage {
  public body: Buffer
  public nonce: Buffer
  public transitIdentity: Buffer
  public mode = 'direct'

  constructor(public timestamp = new Date(), public destination = '') {}

  canonical(): Buffer {
    const str = [
      `{`,
      `"mode":"direct",`,
      `"body":"${this.body.toString('base64')}",`,
      `"destination":"${this.destination}",`,
      `"nonce":"${this.nonce.toString('base64')}",`,
      `"timestamp":${this.timestamp.valueOf()},`,
      `"transitIdentity":"${this.transitIdentity.toString('base64')}"`,
      `}`,
    ].join('')
    return Buffer.from(str)
  }

  writeBody(body: Buffer, recipientIdentity: Buffer, transitKeyPair: nacl.BoxKeyPair) {
    this.nonce = Buffer.from(randomBytes(box.nonceLength))
    this.body = Buffer.from(box(body, this.nonce, recipientIdentity, transitKeyPair.secretKey))
    this.transitIdentity = Buffer.from(transitKeyPair.publicKey)
  }

  open(recipientSecret: Uint8Array): Buffer {
    const opened = box.open(this.body, this.nonce, this.transitIdentity, recipientSecret)
    if (!opened) {
      throw new Error('Unable to decrypt')
    }
    return Buffer.from(opened)
  }

  static parse(str: string): DirectMessage {
    const dm = new DirectMessage()
    const parsed = JSON.parse(str)
    dm.timestamp = parsed.timestamp
    dm.destination = parsed.destination
    dm.body = Buffer.from(parsed.body, 'base64')
    dm.nonce = Buffer.from(parsed.nonce, 'base64')
    dm.transitIdentity = Buffer.from(parsed.transitIdentity, 'base64')
    return dm
  }
}
