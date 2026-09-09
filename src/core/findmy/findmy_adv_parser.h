#pragma once

#include <cstdint>
#include <cstddef>

// ===========================================================================
//  Apple Find My advertisement header parsing.
//
//  Apple concatenates several Continuity messages inside ONE manufacturer-data
//  field (company 0x004C), each as type + length + payload:
//
//      4C 00 | 12 02 6E 01 | 07 11 06 ...
//      ^^^^^   ^^^^^^^^^^^^  ^^^^^^^^^^^^
//      Apple   Find My (2 B) Proximity Pairing (17 B)
//
//  For Find My (type 0x12) the LENGTH byte carries the distinction that
//  matters for tracker detection:
//
//      0x02 = short form — the device takes part in the Find My network and
//             its owner is nearby. Sent by iPhones, iPads, Macs, Watches and
//             by accessories still paired to their owner's device.
//      0x19 = long form with the rotating public key — an accessory in the
//             "separated" state, i.e. away from its owner. This is the
//             stalking-relevant case.
//
//  This mirrors what FmdnParser already does on the Google side, where frame
//  type 0x40 means "owner nearby" and 0x41 means "separated". Apple encodes
//  the same distinction in the length byte instead of a frame type.
//
//  Deliberately NOT decided here: which kind of accessory it is. Apple designs
//  all Find My devices to advertise identically, so an AirTag, a Chipolo, a
//  Pebblebee and an AirPods case are indistinguishable in the separated state
//  — and all four are equally usable for tracking someone.
//
//  Field layout from public reverse-engineering work (OpenHaystack, AirGuard,
//  and Heinrich/Stute/Hollick "Who Can Find My Devices?", 2021), the same
//  sources findmy_payload_parser.h cites. Purely passive — nothing is
//  decrypted and no connection is made.
// ===========================================================================

namespace FindMyAdv {

constexpr uint8_t COMPANY_APPLE_LO = 0x4C;  // company 0x004C, little-endian
constexpr uint8_t COMPANY_APPLE_HI = 0x00;

constexpr uint8_t TYPE_FIND_MY = 0x12;

constexpr uint8_t LEN_OWNER_NEARBY = 0x02;  // owner is close by
constexpr uint8_t LEN_SEPARATED    = 0x19;  // accessory away from its owner

struct FindMyAdvResult {
    // A Find My message is present at all.
    bool detected = false;

    // Length byte was 0x19: accessory separated from its owner.
    bool separated = false;

    // Raw length byte, so callers can log unknown forms instead of guessing.
    // Apple has changed the format before; a length that is neither 0x02 nor
    // 0x19 is reported as detected-but-not-separated rather than assumed to be
    // a tracker.
    uint8_t length = 0;

    // Where the Find My payload starts inside the manufacturer data, and how
    // long it is — feed these straight into parseFindMyPayload() instead of
    // assuming the message sits at a fixed offset.
    size_t  payloadOffset = 0;
    uint8_t payloadLength = 0;
};

// mfg/len: the raw manufacturer data INCLUDING the two company-ID bytes,
// exactly as NimBLE's getManufacturerData() returns it.
FindMyAdvResult parse(const uint8_t* mfg, size_t len);

}  // namespace FindMyAdv
