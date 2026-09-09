#include <gtest/gtest.h>
#include "core/findmy/findmy_adv_parser.h"

// All byte sequences below are shapes taken from real captures. Rotating key
// material is zeroed out — only the company ID, type and length bytes carry
// the meaning under test here.

// 4C 00 | 12 19 | <25 bytes of rotating key> = 29 bytes.
// An accessory in the separated state: away from its owner, broadcasting so
// the Find My network can locate it. AirTag, Chipolo, Pebblebee and an AirPods
// case all look like this — deliberately indistinguishable.
TEST(FindMyAdv, DetectsSeparatedAccessory) {
    uint8_t data[29] = {0x4C, 0x00, 0x12, 0x19};
    auto r = FindMyAdv::parse(data, sizeof(data));
    EXPECT_TRUE(r.detected);
    EXPECT_TRUE(r.separated);
    EXPECT_EQ(r.length, 0x19);
    EXPECT_EQ(r.payloadOffset, 4u);
    EXPECT_EQ(r.payloadLength, 25);
}

// 4C 00 | 12 02 6E 01 | 07 11 <17 bytes> = 25 bytes exactly.
// AirPods whose owner is right there: Find My short form plus Proximity
// Pairing. The total length reaches 25 bytes, so a size-based check reads this
// as a separated tracker. It is not one — the short form means the opposite.
TEST(FindMyAdv, AirPodsWithOwnerNearbyAreNotSeparated) {
    uint8_t data[25] = {0x4C, 0x00, 0x12, 0x02, 0x6E, 0x01, 0x07, 0x11};
    auto r = FindMyAdv::parse(data, sizeof(data));
    EXPECT_TRUE(r.detected);
    EXPECT_FALSE(r.separated);
    EXPECT_EQ(r.length, 0x02);
}

// 4C 00 | 12 02 6E 00 = 6 bytes. A phone or watch, nothing else in the packet.
// This is what most Apple devices look like: 19533 of 20573 captured short-form
// payloads were exactly this size.
TEST(FindMyAdv, PlainAppleDeviceIsDetectedButNotSeparated) {
    const uint8_t data[] = {0x4C, 0x00, 0x12, 0x02, 0x6E, 0x00};
    auto r = FindMyAdv::parse(data, sizeof(data));
    EXPECT_TRUE(r.detected);
    EXPECT_FALSE(r.separated);
}

// Nearby Info (0x10) only — an Apple device that sends no Find My message.
TEST(FindMyAdv, IgnoresAppleDataWithoutFindMyMessage) {
    const uint8_t data[] = {0x4C, 0x00, 0x10, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_FALSE(FindMyAdv::parse(data, sizeof(data)).detected);
}

// Samsung (0x0075). Long enough to pass a size check, but not Apple.
TEST(FindMyAdv, IgnoresOtherManufacturers) {
    uint8_t data[29] = {0x75, 0x00, 0x12, 0x19};
    EXPECT_FALSE(FindMyAdv::parse(data, sizeof(data)).detected);
}

// Defensive: type 0x12 behind another message. Not observed in 22062 captured
// payloads — 0x12 was always first — but the walk should not depend on that.
TEST(FindMyAdv, FindsFindMyMessageBehindAnother) {
    uint8_t data[38] = {0x4C, 0x00,
                        0x10, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
                        0x12, 0x19};
    auto r = FindMyAdv::parse(data, sizeof(data));
    EXPECT_TRUE(r.detected);
    EXPECT_TRUE(r.separated);
    EXPECT_EQ(r.payloadOffset, 11u);
}

// A length byte claiming more than is there ends the chain instead of reading
// past the buffer. 27 of 11527 captured Apple payloads were malformed this way.
TEST(FindMyAdv, DoesNotReadPastATruncatedMessage) {
    const uint8_t data[] = {0x4C, 0x00, 0x12, 0x19, 0x01, 0x02};
    EXPECT_FALSE(FindMyAdv::parse(data, sizeof(data)).detected);
}

// An unknown length is reported, not assumed to be a tracker. Apple has
// changed the format before; the long form must be proven, not inferred.
TEST(FindMyAdv, UnknownLengthIsNotTreatedAsSeparated) {
    uint8_t data[12] = {0x4C, 0x00, 0x12, 0x08};
    auto r = FindMyAdv::parse(data, sizeof(data));
    EXPECT_TRUE(r.detected);
    EXPECT_FALSE(r.separated);
    EXPECT_EQ(r.length, 0x08);
}

TEST(FindMyAdv, HandlesEmptyAndTooShortInput) {
    const uint8_t data[] = {0x4C, 0x00, 0x12};
    EXPECT_FALSE(FindMyAdv::parse(nullptr, 0).detected);
    EXPECT_FALSE(FindMyAdv::parse(data, sizeof(data)).detected);
}

// Regression guard for the check this parser replaced:
//     isOfflineFinding = (mfg.size() >= 25);
// Both payloads below reach 25 bytes, so that check called both of them
// separated trackers. Only the second one is. In a 7-day capture 1040 of 2528
// "Find My Tracker detected" reports were the first shape — AirPods sitting
// next to their owner.
TEST(FindMyAdv, SizeAloneDoesNotDecideSeparation) {
    uint8_t airpodsNearOwner[25] = {0x4C, 0x00, 0x12, 0x02, 0x6E, 0x01, 0x07, 0x11};
    uint8_t separatedTracker[29] = {0x4C, 0x00, 0x12, 0x19};

    ASSERT_GE(sizeof(airpodsNearOwner), 25u);
    ASSERT_GE(sizeof(separatedTracker), 25u);

    EXPECT_FALSE(FindMyAdv::parse(airpodsNearOwner, sizeof(airpodsNearOwner)).separated);
    EXPECT_TRUE(FindMyAdv::parse(separatedTracker, sizeof(separatedTracker)).separated);
}
