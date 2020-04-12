"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_1 = require("buffer/");
const envelope_1 = require("./envelope");
const shared_message_1 = require("./shared_message");
const direct_message_1 = require("./direct_message");
function directMessageEnvelope({ body, destination, senderIdentity, transit, recipientIdentity, }) {
    const dm = new direct_message_1.DirectMessage(new Date(), destination);
    dm.writeBody(buffer_1.Buffer.from(body), buffer_1.Buffer.from(recipientIdentity), transit);
    const e = new envelope_1.Envelope(dm.canonical());
    e.sign(senderIdentity);
    return e;
}
exports.directMessageEnvelope = directMessageEnvelope;
function sharedMessageEnvelope({ body, destination, senderIdentity, sharedSecret, }) {
    const sm = new shared_message_1.SharedMessage(new Date(), destination);
    sm.writeBody(buffer_1.Buffer.from(body), buffer_1.Buffer.from(sharedSecret));
    const e = new envelope_1.Envelope(sm.canonical());
    e.sign(senderIdentity);
    return e;
}
exports.sharedMessageEnvelope = sharedMessageEnvelope;
//# sourceMappingURL=seam.js.map