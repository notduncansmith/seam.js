import { Buffer } from 'buffer/'
import nacl from 'tweetnacl'

type IdentityKeyPair = nacl.SignKeyPair

export class Envelope {
  public author: Buffer
  public signature: Buffer

  constructor(public message: Buffer) {}

  public JSON() {
    const author = Buffer.from(this.author).toString('base64')
    const signature = Buffer.from(this.signature).toString('base64')
    return JSON.stringify({ ...this, author, signature })
  }

  public sign(ikp: IdentityKeyPair) {
    const hash = nacl.hash(this.message)
    this.signature = Buffer.from(nacl.sign.detached(hash, ikp.secretKey))
    this.author = Buffer.from(ikp.publicKey)
  }

  public verify() {
    const hash = nacl.hash(this.message)
    return nacl.sign.detached.verify(hash, this.signature, this.author)
  }

  static parse(str: string): Envelope {
    const parsed = JSON.parse(str) as { message: string; author: string; signature: string }
    const e = new Envelope(Buffer.from(parsed.message, 'base64'))
    e.author = Buffer.from(parsed.author, 'base64')
    e.signature = Buffer.from(parsed.signature, 'base64')
    return e
  }
}
