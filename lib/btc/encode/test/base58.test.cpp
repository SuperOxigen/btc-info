// Bitcoin Info - Encoders - Base58 Encoder - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <string.h>

#include <gtest/gtest.h>

#include "btc/encode/base58.hpp"
#include "btc/encode/hex.hpp"

namespace btc {
namespace encode {
namespace test {
namespace {
const std::string kSampleWalletAddressHex =
    "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8";
const std::vector<uint8_t> kSampleWalletAddress =
    HexDecode(kSampleWalletAddressHex);
const std::string kSampleWalletAddressBase58 =
    "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";
}  // namespace

TEST(Base58Test, IsBase58String) {
  EXPECT_TRUE(IsBase58String(""));
  EXPECT_TRUE(IsBase58String("JxF12TrwUP45BMd"));
  EXPECT_TRUE(IsBase58String(kSampleWalletAddressBase58));

  // Forbidden alphanumeric characters.
  EXPECT_FALSE(IsBase58String("JxF12TOwUP45BMd")) << "Has 'O'";
  EXPECT_FALSE(IsBase58String("JxF12TrwUP40BMd")) << "Has '0'";
  EXPECT_FALSE(IsBase58String("JxF12TrwlP45BMd")) << "Has 'l'";
  EXPECT_FALSE(IsBase58String("JxFI2TrwUP45BMd")) << "Has 'I'";

  // Forbidden non-alphanumeric characters (non-exhaustive).
  EXPECT_FALSE(IsBase58String("JxF12Tr wUP45BMd"));
  EXPECT_FALSE(IsBase58String("aGVsbG8="));
  EXPECT_FALSE(IsBase58String("abcd/abcd"));
  EXPECT_FALSE(IsBase58String("JxF12TrwUP?45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12T-rwUP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12TrwUP4+5BMd"));
  EXPECT_FALSE(IsBase58String("Jx&F12TrwUP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12Trw$UP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12TrwUP45_BMd"));
  EXPECT_FALSE(IsBase58String("JxF1<2TrwUP45BMd"));

  // Forbidden special characters (non-exhaustive)
  EXPECT_FALSE(IsBase58String("JxF12T\rwUP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12TrwU\nP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF1\t2TrwUP45BMd"));
  EXPECT_FALSE(IsBase58String("JxF12TrwUP45\bBMd"));
  EXPECT_FALSE(IsBase58String("JxF12\eTrwUP45BMd"));
}

TEST(Base58Test, BasicEncode) {
  // From string.
  std::string b58 = Base58Encode("Hello World");
  EXPECT_EQ(b58, "JxF12TrwUP45BMd");
  // From vector<uint8_t>.
  // This is an example bitcoin wallet.
  b58 = Base58Encode(kSampleWalletAddress);
  EXPECT_EQ(b58, kSampleWalletAddressBase58);
  // All zeros.
  for (size_t zeros = 1; zeros < 50; zeros++) {
    const std::vector<uint8_t> all_zeros(zeros);
    b58 = Base58Encode(all_zeros);
    const std::string expected_b58(zeros, '1');
    EXPECT_EQ(b58, expected_b58) << "zeros = " << zeros;
  }
  // Empty.
  b58 = Base58Encode(std::vector<uint8_t>());
  EXPECT_EQ(b58, "");
}

TEST(Base58Test, BasicDecode) {
  std::string str_res = Base58DecodeToString("JxF12TrwUP45BMd");
  EXPECT_EQ(str_res, "Hello World");

  const std::vector<uint8_t> decoded_wallet =
      Base58Decode(kSampleWalletAddressBase58);
  const std::string decoded_wallet_hex = HexEncode(decoded_wallet);
  EXPECT_EQ(decoded_wallet_hex, kSampleWalletAddressHex);

  // All zeros.
  for (size_t zeros = 1; zeros < 50; zeros++) {
    const std::string all_zeros_b58(zeros, '1');
    std::vector<uint8_t> res = Base58Decode(all_zeros_b58);
    const std::vector<uint8_t> expected_result(zeros, 0);
    EXPECT_EQ(res, expected_result) << "zeros = " << zeros;
  }
  EXPECT_EQ(Base58DecodeToString(""), "");
}

TEST(Base58Test, TruncatedDecode) {
  uint8_t buffer[64];
  const size_t expected_size = kSampleWalletAddress.size();
  size_t res = Base58Decode(kSampleWalletAddressBase58, buffer, 0);
  EXPECT_EQ(res, expected_size);

  for (size_t buffer_size = 1; buffer_size <= expected_size; buffer_size++) {
    memset(buffer, 0, sizeof(buffer));
    res = Base58Decode(kSampleWalletAddressBase58, buffer, buffer_size);
    EXPECT_EQ(res, expected_size);

    std::vector<uint8_t> expected_result(
        kSampleWalletAddress.begin(),
        kSampleWalletAddress.begin() + buffer_size);
    expected_result.insert(
        expected_result.end(), sizeof(buffer) - buffer_size, 0);
    const std::vector<uint8_t> result(buffer, buffer + sizeof(buffer));
    ASSERT_EQ(result, expected_result) << "buffer_size = " << buffer_size;
  }
}
}  // namespace test
}  // namespace encode
}  // namespace btc
