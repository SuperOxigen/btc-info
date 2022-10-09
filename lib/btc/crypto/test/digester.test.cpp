// Bitcoin Info - Cryptography - Digester - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <gtest/gtest.h>

#include "btc/crypto/digester.hpp"
#include "btc/encode/hex.hpp"

namespace btc {
namespace crypto {
namespace test {
using ::btc::encode::HexDecode;
using ::btc::encode::HexEncode;
namespace {
const std::vector<uint8_t> kEmptyVector;
const std::string kEmptyString;
}  // namespace

TEST(DigesterTest, RipeMd160) {
  // Not supported.
  auto digester = Digester::New(kRipeMd160);
  ASSERT_FALSE(digester);
  GTEST_SKIP() << "RIPEMD-160 not supported yet";
  return;
  EXPECT_EQ(digester->algorithm(), kRipeMd160);
  EXPECT_EQ(digester->digest_length(), kRipeMd160DigestLength);

  std::string hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, "9c1185a5c5e9fc54612808977ee8f548b2258d31");

  EXPECT_TRUE(digester->Update("abc"));
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

  EXPECT_TRUE(digester->Update("defghijklmnopqrstuvwxyz"));
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");

  EXPECT_EQ(digester->Count(), 26);

  digester->Reset();
  EXPECT_EQ(digester->Count(), 0);
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, "9c1185a5c5e9fc54612808977ee8f548b2258d31");

  for (size_t i = 0; i < 8; i++) {
    EXPECT_TRUE(digester->Update("1234567890"));
  }
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
}

TEST(DigesterTest, Sha256) {
  auto digester = Digester::New(kSha256);
  ASSERT_TRUE(digester);

  EXPECT_EQ(digester->algorithm(), kSha256);
  EXPECT_EQ(digester->digest_length(), kSha256DigestLength);

  std::string hex_digest = HexEncode(digester->Finalize());
  const std::string kEmptyDigestHex =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  EXPECT_TRUE(digester->Update("abc"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAbcDigestHex =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  EXPECT_EQ(hex_digest, kAbcDigestHex);

  EXPECT_TRUE(digester->Update("defghijklmnopqrstuvwxyz"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAlphabetDigestHex =
      "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73";
  EXPECT_EQ(hex_digest, kAlphabetDigestHex);
  EXPECT_EQ(digester->Count(), 26);

  digester->Reset();
  EXPECT_EQ(digester->Count(), 0);
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  for (size_t i = 0; i < 8; i++) {
    ASSERT_TRUE(digester->Update("1234567890")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 80);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kRepeatedDigitsDigestHex =
      "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e";
  EXPECT_EQ(hex_digest, kRepeatedDigitsDigestHex);

  digester->Reset();
  for (size_t i = 0; i < 100000; i++) {
    ASSERT_TRUE(digester->Update("aaaaaaaaaa")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 1000000);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kOneMillionADigestHex =
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
  EXPECT_EQ(hex_digest, kOneMillionADigestHex);
}

TEST(DigesterTest, Sha256Sha256) {
  auto digester = Digester::New(kSha256Sha256);
  ASSERT_TRUE(digester);

  EXPECT_EQ(digester->algorithm(), kSha256Sha256);
  EXPECT_EQ(digester->digest_length(), kSha256DigestLength);

  std::string hex_digest = HexEncode(digester->Finalize());
  const std::string kEmptyDigestHex =
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  EXPECT_TRUE(digester->Update("abc"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAbcDigestHex =
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
  EXPECT_EQ(hex_digest, kAbcDigestHex);

  EXPECT_TRUE(digester->Update("defghijklmnopqrstuvwxyz"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAlphabetDigestHex =
      "ca139bc10c2f660da42666f72e89a225936fc60f193c161124a672050c434671";
  EXPECT_EQ(hex_digest, kAlphabetDigestHex);
  EXPECT_EQ(digester->Count(), 26);

  digester->Reset();
  EXPECT_EQ(digester->Count(), 0);
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  for (size_t i = 0; i < 8; i++) {
    ASSERT_TRUE(digester->Update("1234567890")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 80);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kRepeatedDigitsDigestHex =
      "37222523dc0f0b26ccfc58cf4627c0a8ab0b0bd3eac0e550ddc901cab912ea58";
  EXPECT_EQ(hex_digest, kRepeatedDigitsDigestHex);

  digester->Reset();
  for (size_t i = 0; i < 100000; i++) {
    ASSERT_TRUE(digester->Update("aaaaaaaaaa")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 1000000);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kOneMillionADigestHex =
      "80d1189477563e1b5206b2749f1afe4807e5705e8bd77887a60187a712156688";
  EXPECT_EQ(hex_digest, kOneMillionADigestHex);
}

TEST(DigesterTest, Sha256RipeMd160) {
  auto digester = Digester::New(kSha256RipeMd160);
  ASSERT_TRUE(digester);

  EXPECT_EQ(digester->algorithm(), kSha256RipeMd160);
  EXPECT_EQ(digester->digest_length(), kRipeMd160DigestLength);

  std::string hex_digest = HexEncode(digester->Finalize());
  const std::string kEmptyDigestHex =
      "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb";
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  EXPECT_TRUE(digester->Update("abc"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAbcDigestHex = "bb1be98c142444d7a56aa3981c3942a978e4dc33";
  EXPECT_EQ(hex_digest, kAbcDigestHex);

  EXPECT_TRUE(digester->Update("defghijklmnopqrstuvwxyz"));
  hex_digest = HexEncode(digester->Finalize());
  const std::string kAlphabetDigestHex =
      "c286a1af0947f58d1ad787385b1c2c4a976f9e71";
  EXPECT_EQ(hex_digest, kAlphabetDigestHex);
  EXPECT_EQ(digester->Count(), 26);

  digester->Reset();
  EXPECT_EQ(digester->Count(), 0);
  hex_digest = HexEncode(digester->Finalize());
  EXPECT_EQ(hex_digest, kEmptyDigestHex);

  for (size_t i = 0; i < 8; i++) {
    ASSERT_TRUE(digester->Update("1234567890")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 80);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kRepeatedDigitsDigestHex =
      "175a89feae4e48f03fbb2dd0878fb4944c55ef41";
  EXPECT_EQ(hex_digest, kRepeatedDigitsDigestHex);

  digester->Reset();
  for (size_t i = 0; i < 100000; i++) {
    ASSERT_TRUE(digester->Update("aaaaaaaaaa")) << "i = " << i;
  }
  EXPECT_EQ(digester->Count(), 1000000);
  hex_digest = HexEncode(digester->Finalize());
  const std::string kOneMillionADigestHex =
      "f9be0e104ef2ed83a7ddb4765780951405e56ba4";
  EXPECT_EQ(hex_digest, kOneMillionADigestHex);
}
}  // namespace test
}  // namespace crypto
}  // namespace btc
