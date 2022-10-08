// Bitcoin Info - Cryptography - Digest Algorithm - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <gtest/gtest.h>

#include "btc/crypto/digest.hpp"
#include "btc/encode/hex.hpp"

namespace btc {
namespace crypto {
namespace test {
using ::btc::encode::HexDecode;
namespace {
const std::vector<uint8_t> kEmptyVector;
const std::string kEmptyString;
}  // namespace

TEST(DigestTest, Sha256) {
  // SHA-256 with no input.
  const std::vector<uint8_t> kEmptyDigest = HexDecode(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  std::vector<uint8_t> digest(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256(nullptr, 0, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest.assign(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256(kEmptyString, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest.assign(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256(kEmptyVector, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256(nullptr, 0);
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256(kEmptyString);
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256(kEmptyVector);
  EXPECT_EQ(digest, kEmptyDigest);

  // SHA-256 of "abc"
  const std::vector<uint8_t> kAbcDigest = HexDecode(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  digest = Sha256("abc");
  EXPECT_EQ(digest, kAbcDigest);

  // SHA-256 of "hello"
  const std::vector<uint8_t> kHelloDigest = HexDecode(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  digest = Sha256("hello");
  EXPECT_EQ(digest, kHelloDigest);
}

TEST(DigestTest, Sha256Sha256) {
  // SHA-256-SHA-256 with no input.
  const std::vector<uint8_t> kEmptyDigest = HexDecode(
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

  std::vector<uint8_t> digest(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256Sha256(nullptr, 0, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest.assign(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256Sha256(kEmptyString, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest.assign(kSha256DigestLength, 0);
  EXPECT_TRUE(Sha256Sha256(kEmptyVector, digest.data()));
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256Sha256(nullptr, 0);
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256Sha256(kEmptyString);
  EXPECT_EQ(digest, kEmptyDigest);

  digest = Sha256Sha256(kEmptyVector);
  EXPECT_EQ(digest, kEmptyDigest);

  // SHA-256-SHA-256 of "abc"
  const std::vector<uint8_t> kAbcDigest = HexDecode(
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
  digest = Sha256Sha256("abc");
  EXPECT_EQ(digest, kAbcDigest);

  // SHA-256-SHA-256 of "hello"
  const std::vector<uint8_t> kHelloDigest = HexDecode(
      "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
  digest = Sha256Sha256("hello");
  EXPECT_EQ(digest, kHelloDigest);
}

TEST(DigestTest, Sha256RipeMd160) {
  // SHA-256-RIPEMD-160 of "hello"
  const std::vector<uint8_t> kHelloDigest =
      HexDecode("b6a9c8c230722b7c748331a8b450f05566dc7d0f");
  const std::vector<uint8_t> digest = Sha256RipeMd160("hello");
  EXPECT_EQ(digest, kHelloDigest);
}
}  // namespace test
}  // namespace crypto
}  // namespace btc
