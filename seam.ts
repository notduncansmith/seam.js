import { Buffer } from 'buffer/'
import { Envelope } from './envelope'
import { SharedMessage } from './shared_message'
import { DirectMessage } from './direct_message'

export function directMessageEnvelope({
  body,
  destination,
  senderIdentity,
  transit,
  recipientIdentity,
}: {
  body: Uint8Array
  destination: string
  senderIdentity: nacl.SignKeyPair
  transit: nacl.BoxKeyPair
  recipientIdentity: Uint8Array
}): Envelope {
  const dm = new DirectMessage(new Date(), destination)
  dm.writeBody(Buffer.from(body), Buffer.from(recipientIdentity), transit)

  const e = new Envelope(dm.canonical())
  e.sign(senderIdentity)

  return e
}

export function sharedMessageEnvelope({
  body,
  destination,
  senderIdentity,
  sharedSecret,
}: {
  body: Uint8Array
  destination: string
  senderIdentity: nacl.SignKeyPair
  sharedSecret: Uint8Array
}): Envelope {
  const sm = new SharedMessage(new Date(), destination)
  sm.writeBody(Buffer.from(body), Buffer.from(sharedSecret))

  const e = new Envelope(sm.canonical())
  e.sign(senderIdentity)

  return e
}
