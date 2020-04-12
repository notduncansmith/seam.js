"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const js_sha512_1 = require("js-sha512");
class Envelope {
    constructor(message) {
        this.message = message;
    }
    JSON() {
        const author = buffer_1.Buffer.from(this.author).toString('base64');
        const signature = buffer_1.Buffer.from(this.signature).toString('base64');
        return JSON.stringify(Object.assign(Object.assign({}, this), { author, signature }));
    }
    sign(ikp) {
        const hash = js_sha512_1.sha512.create();
        hash.update(this.message);
        this.signature = buffer_1.Buffer.from(tweetnacl_1.default.sign.detached(buffer_1.Buffer.from(hash.array()), ikp.secretKey));
        this.author = buffer_1.Buffer.from(ikp.publicKey);
    }
    verify() {
        const hash = js_sha512_1.sha512.create();
        hash.update(this.message);
        return tweetnacl_1.default.sign.detached.verify(buffer_1.Buffer.from(hash.array()), this.signature, this.author);
    }
    static parse(str) {
        const parsed = JSON.parse(str);
        const e = new Envelope(buffer_1.Buffer.from(parsed.message, 'base64'));
        e.author = buffer_1.Buffer.from(parsed.author, 'base64');
        e.signature = buffer_1.Buffer.from(parsed.signature, 'base64');
        return e;
    }
}
exports.Envelope = Envelope;
//# sourceMappingURL=envelope.js.map