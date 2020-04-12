"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_1 = require("buffer/");
const tweetnacl_1 = require("tweetnacl");
class SharedMessage {
    constructor(timestamp = new Date(), destination = '') {
        this.timestamp = timestamp;
        this.destination = destination;
        this.mode = 'shared';
    }
    canonical() {
        const str = [
            `{`,
            `"mode":"shared",`,
            `"body":"${this.body.toString('base64')}",`,
            `"destination":"${this.destination}",`,
            `"nonce":"${this.nonce.toString('base64')}",`,
            `"timestamp":${this.timestamp.valueOf()}`,
            `}`,
        ].join('');
        return buffer_1.Buffer.from(str);
    }
    writeBody(body, secret) {
        this.nonce = buffer_1.Buffer.from(tweetnacl_1.randomBytes(tweetnacl_1.secretbox.nonceLength));
        this.body = buffer_1.Buffer.from(tweetnacl_1.secretbox(body, this.nonce, secret));
    }
    open(secret) {
        return buffer_1.Buffer.from(tweetnacl_1.secretbox.open(this.body, this.nonce, secret));
    }
    static parse(str) {
        const dm = new SharedMessage();
        const parsed = JSON.parse(str);
        dm.timestamp = parsed.timestamp;
        dm.destination = parsed.destination;
        dm.body = buffer_1.Buffer.from(parsed.body, 'base64');
        dm.nonce = buffer_1.Buffer.from(parsed.nonce, 'base64');
        return dm;
    }
}
exports.SharedMessage = SharedMessage;
//# sourceMappingURL=shared_message.js.map