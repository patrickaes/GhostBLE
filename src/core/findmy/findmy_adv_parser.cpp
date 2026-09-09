#include "findmy_adv_parser.h"

namespace FindMyAdv {

FindMyAdvResult parse(const uint8_t* mfg, size_t len) {
    FindMyAdvResult result;

    // Company ID (2 B) plus at least one type/length pair.
    if (mfg == nullptr || len < 4) {
        return result;
    }

    if (mfg[0] != COMPANY_APPLE_LO || mfg[1] != COMPANY_APPLE_HI) {
        return result;
    }

    // Walk the Continuity chain rather than reading a fixed offset. In 22062
    // captured Apple payloads type 0x12 was always the first message, so this
    // walk is defensive, not a fix for anything observed — but reading the
    // length byte correctly means locating the message first, and Apple is
    // free to reorder.
    size_t i = 2;
    while (i + 2 <= len) {
        const uint8_t type      = mfg[i];
        const uint8_t msgLength = mfg[i + 1];

        // A length pointing past the end ends the chain. Whatever was read
        // cleanly up to here stays valid; the rest is not guessed at.
        if (i + 2 + msgLength > len) {
            break;
        }

        if (type == TYPE_FIND_MY) {
            result.detected      = true;
            result.length        = msgLength;
            result.payloadOffset = i + 2;
            result.payloadLength = msgLength;
            result.separated     = (msgLength == LEN_SEPARATED);
            return result;
        }

        i += 2 + msgLength;
    }

    return result;
}

}  // namespace FindMyAdv
