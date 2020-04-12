"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_1 = require("buffer/");
const tweetnacl_1 = require("tweetnacl");
class DirectMessage {
    constructor(timestamp = new Date(), destination = '') {
        this.timestamp = timestamp;
        this.destination = destination;
        this.mode = 'direct';
    }
    canonical() {
        const str = [
            `{`,
            `"mode":"direct",`,
            `"body":"${this.body.toString('base64')}",`,
            `"destination":"${this.destination}",`,
            `"nonce":"${this.nonce.toString('base64')}",`,
            `"timestamp":${this.timestamp.valueOf()},`,
            `"transitIdentity":"${this.transitIdentity.toString('base64')}"`,
            `}`,
        ].join('');
        return buffer_1.Buffer.from(str);
    }
    writeBody(body, recipientIdentity, transitKeyPair) {
        this.nonce = buffer_1.Buffer.from(tweetnacl_1.randomBytes(tweetnacl_1.box.nonceLength));
        this.body = buffer_1.Buffer.from(tweetnacl_1.box(body, this.nonce, recipientIdentity, transitKeyPair.secretKey));
        this.transitIdentity = buffer_1.Buffer.from(transitKeyPair.publicKey);
    }
    open(recipientSecret) {
        const opened = tweetnacl_1.box.open(this.body, this.nonce, this.transitIdentity, recipientSecret);
        if (!opened) {
            throw new Error('Unable to decrypt');
        }
        return buffer_1.Buffer.from(opened);
    }
    static parse(str) {
        const dm = new DirectMessage();
        const parsed = JSON.parse(str);
        dm.timestamp = parsed.timestamp;
        dm.destination = parsed.destination;
        dm.body = buffer_1.Buffer.from(parsed.body, 'base64');
        dm.nonce = buffer_1.Buffer.from(parsed.nonce, 'base64');
        dm.transitIdentity = buffer_1.Buffer.from(parsed.transitIdentity, 'base64');
        return dm;
    }
}
exports.DirectMessage = DirectMessage;
//# sourceMappingURL=direct_message.js.map