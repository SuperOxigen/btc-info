// Bitcoin Info - Encoders - Hexadecimal Encoder - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <gtest/gtest.h>

#include "btc/encode/hex.hpp"

namespace btc {
namespace encode {
namespace test {
namespace {
const std::string kEmptyString = "";
const std::string kHelloWorld = "Hello, World!";
const std::string kNotHex = "not hex characters";
const std::string kHexHelloWorld = "48656c6c6f2c20576f726c6421";
const std::string kHexHelloWorldUpper = "48656C6C6F2C20576F726C6421";
const std::string kHexHelloWorldReverse = "21646c726f57202c6f6c6c6548";
const std::vector<uint8_t> kEmptyVector;
const std::vector<uint8_t>
    kHelloWorldVector(kHelloWorld.begin(), kHelloWorld.end());

constexpr size_t kHelloWorldSize = 13;

constexpr bool kForward = false;
constexpr bool kReverse = true;
}  // namespace

TEST(HexTest, IsHexString) {
  EXPECT_TRUE(IsHexString(""));
  EXPECT_TRUE(IsHexString(kHexHelloWorld));
  EXPECT_TRUE(IsHexString(kHexHelloWorldUpper));
  EXPECT_TRUE(IsHexString(kHexHelloWorldReverse));
  EXPECT_TRUE(IsHexString("deadbeaf"));
  EXPECT_TRUE(IsHexString("1ee7"));
  EXPECT_TRUE(IsHexString("abcdef"));
  EXPECT_TRUE(IsHexString("abcdefabcdef"));

  EXPECT_FALSE(IsHexString("abcde"));  // Odd length
  EXPECT_FALSE(IsHexString(kNotHex));
  EXPECT_FALSE(IsHexString(kHelloWorld));
}

TEST(HexTest, EncodeEmpty) {
  EXPECT_EQ(kEmptyString, HexEncode(kHelloWorldVector.data(), 0));
  EXPECT_EQ(kEmptyString, HexEncode(kEmptyString));
  EXPECT_EQ(kEmptyString, HexEncode(kEmptyVector));
}

TEST(HexTest, Encode) {
  // Raw pointer
  EXPECT_EQ(
      kHexHelloWorld,
      HexEncode(kHelloWorldVector.data(), kHelloWorldVector.size(), kForward));
  EXPECT_EQ(
      kHexHelloWorldReverse,
      HexEncode(kHelloWorldVector.data(), kHelloWorldVector.size(), kReverse));
  // Vector
  EXPECT_EQ(kHexHelloWorld, HexEncode(kHelloWorldVector, kForward));
  EXPECT_EQ(kHexHelloWorldReverse, HexEncode(kHelloWorldVector, kReverse));
  // String
  EXPECT_EQ(kHexHelloWorld, HexEncode(kHelloWorld, kForward));
  EXPECT_EQ(kHexHelloWorldReverse, HexEncode(kHelloWorld, kReverse));
}

TEST(HexTest, DecodeBadParameters) {
  uint8_t buffer[64];
  EXPECT_EQ(0, HexDecode(kHelloWorld, buffer, sizeof(buffer)));
  EXPECT_EQ(0, HexDecode(kNotHex, buffer, sizeof(buffer)));

  EXPECT_EQ(kEmptyVector, HexDecode(kHelloWorld));
  EXPECT_EQ(kEmptyVector, HexDecode(kNotHex));

  EXPECT_EQ(kEmptyString, HexDecodeToString(kHelloWorld));
  EXPECT_EQ(kEmptyString, HexDecodeToString(kNotHex));
}

TEST(HexTest, DecodeEmpty) {
  uint8_t buffer[64];
  EXPECT_EQ(0, HexDecode(kEmptyString, buffer, sizeof(buffer)));

  EXPECT_EQ(kEmptyVector, HexDecode(kEmptyString));

  EXPECT_EQ(kEmptyString, HexDecodeToString(kEmptyString));
}

TEST(HexTest, Decode) {
  uint8_t buffer[64];
  const size_t forward_res = HexDecode(kHexHelloWorld, buffer, sizeof(buffer));
  EXPECT_EQ(kHelloWorldSize, forward_res);
  std::vector<uint8_t> vec_out(buffer, &buffer[forward_res]);
  EXPECT_EQ(kHelloWorldVector, vec_out);

  const size_t reverse_res =
      HexDecode(kHexHelloWorldReverse, buffer, sizeof(buffer), kReverse);
  EXPECT_EQ(kHelloWorldSize, reverse_res);
  vec_out.assign(buffer, &buffer[reverse_res]);
  EXPECT_EQ(kHelloWorldVector, vec_out);

  // Direct outputs.
  EXPECT_EQ(kHelloWorldVector, HexDecode(kHexHelloWorld));
  EXPECT_EQ(kHelloWorldVector, HexDecode(kHexHelloWorldUpper));
  EXPECT_EQ(kHelloWorldVector, HexDecode(kHexHelloWorldReverse, kReverse));

  EXPECT_EQ(kHelloWorld, HexDecodeToString(kHexHelloWorld));
  EXPECT_EQ(kHelloWorld, HexDecodeToString(kHexHelloWorldUpper));
  EXPECT_EQ(kHelloWorld, HexDecodeToString(kHexHelloWorldReverse, kReverse));
}
}  // namespace test
}  // namespace encode
}  // namespace btc
