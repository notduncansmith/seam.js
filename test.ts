import assert from 'assert'
import nacl from 'tweetnacl'
import { Buffer } from 'buffer/'
import { directMessageEnvelope, sharedMessageEnvelope } from './seam'
import { SharedMessage, DirectMessage } from './index'
import { Envelope } from './envelope'

const senderIdentity = nacl.sign.keyPair()
const plaintextBody = 'carole baskin fed her husband to the tigers'

describe('A direct message in an envelope', () => {
  const dmRecipient = nacl.box.keyPair.fromSecretKey(
    Buffer.from('CRHgylO+2m/I4ldoA//Y0I5vVbNDIK5b57HpsVA/Rhg=', 'base64')
  )
  const dmTransit = nacl.box.keyPair()
  const envelope = directMessageEnvelope({
    body: Buffer.from(plaintextBody, 'utf8'),
    destination: 'joe@wynnewoodzoo.org',
    senderIdentity,
    transit: dmTransit,
    recipientIdentity: dmRecipient.publicKey,
  })

  it('should be verifiable', () => assert.equal(envelope.verify(), true))

  it('should contain a decryptable body', () => {
    const msg = DirectMessage.parse(envelope.message.toString('utf8'))
    assert.equal(msg.open(dmRecipient.secretKey).toString('utf8'), plaintextBody)
  })

  it('should be parseable from JSON', () => {
    const str = `{"message":"eyJtb2RlIjoiZGlyZWN0IiwiYm9keSI6IkVpbGVpeXJYWVJDTEVyWkVEa1hjV1ZhMnRVOWExdnhDRnZ4K21MTkZQWG5DOUhkVThQNlV1ZXJ5eUNHRDNBZDYrK3FtQVpCNEFkaTRkV1k9IiwiZGVzdGluYXRpb24iOiJqb2VAd3lubmV3b29kem9vLm9yZyIsIm5vbmNlIjoieGI3YlNNYnpzUk03RXlwZzM4bzY0NXhXMHN1akp0NDAiLCJ0aW1lc3RhbXAiOjE1ODY2NTcwNTc1MTQsInRyYW5zaXRJZGVudGl0eSI6ImMrd1E3NWFhSmkyWUdmZHJiOHVtSkM1U3lqRjYzakJqQmR0QXJUVEYxQjA9In0=","author":"L4lQNT91cfdn3CIK8+PCsG7Fez5uLjnOwaX3WwZtUkc=","signature":"yxSHNyuoPRxtHYH2a9kA9LHBxiFTXCKQL4T9+XNSs7j/sEo9PQHhHe+jb/pgQiWx7oCL8nq8PUKREhNhaDKMDA=="}`
    const e = Envelope.parse(str)
    const msg = DirectMessage.parse(e.message.toString('utf8'))
    assert.equal(msg.open(dmRecipient.secretKey).toString('utf8'), plaintextBody)
    assert.equal(e.verify(), true)
  })
})

describe('A shared message in an envelope', () => {
  const sharedSecret = Buffer.from('hUjL1zq3TSyKQIhdYiAhYy1J1mVLciKcmKaTgP4WfKA=', 'base64')
  const envelope = sharedMessageEnvelope({
    body: Buffer.from(plaintextBody, 'utf8'),
    destination: 'joe@wynnewoodzoo.org',
    senderIdentity,
    sharedSecret,
  })

  it('should be verifiable', () => assert.equal(envelope.verify(), true))

  it('should contain a decryptable body', () => {
    const msg = SharedMessage.parse(envelope.message.toString('utf8'))
    assert.equal(msg.open(sharedSecret).toString('utf8'), plaintextBody)
  })

  it('should be parseable from JSON', () => {
    const str = `{"message":"eyJtb2RlIjoic2hhcmVkIiwiYm9keSI6IlkxRWFtczYxTlRjUklhZzRuUnNuWHRtTlJwZm9HNVhqMUZ5WEJLUnJjam4vMlJhdU8yMHF0UEhFK0U1RXNyVk9PeVhzZkxxTnNBVndQaDQ9IiwiZGVzdGluYXRpb24iOiJqb2VAd3lubmV3b29kem9vLm9yZyIsIm5vbmNlIjoiR0I0ZG5kSmpaaWlMaTY1NXpuMUVLTUJGU09RdHgvby8iLCJ0aW1lc3RhbXAiOjE1ODY2NTQxNzkzMTh9","author":"647mhMuS11rGBHimCq5xDNLvarmxuoP78Dpr+29BIMQ=","signature":"zArcWfi86uJYum3Lm8E1ypD0VwDEXs4p1AcEw6pSfIIX9CDG/U+hX+kNbigxnZLLuyuwwF/bdcSVfELLHkdmCA=="}`
    const e = Envelope.parse(str)
    const msg = SharedMessage.parse(e.message.toString('utf8'))
    assert.equal(msg.open(sharedSecret).toString('utf8'), plaintextBody)
    assert.equal(e.verify(), true)
  })
})
