// Bitcoin Info - Wallet - Address - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <gtest/gtest.h>

#include "btc/crypto/ecc_key.hpp"
#include "btc/encode/hex.hpp"
#include "btc/wallet/address.hpp"

namespace btc {
namespace wallet {
namespace test {
using ::btc::crypto::EccPrivateKey;
using ::btc::encode::HexDecode;
using ::btc::encode::HexEncode;

TEST(WalletAddressTest, IsValidPkhAddress) {
  const std::vector<uint8_t> kGoodAddress =
      HexDecode("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8");
  EXPECT_TRUE(PkhAddress::IsValidAddress(kGoodAddress));

  // Bad length.
  std::vector<uint8_t> bad_address = kGoodAddress;
  bad_address.push_back(0xff);
  EXPECT_FALSE(PkhAddress::IsValidAddress(bad_address));
  bad_address.pop_back();
  bad_address.pop_back();
  EXPECT_FALSE(PkhAddress::IsValidAddress(bad_address));

  // Bad checksum.
  bad_address = kGoodAddress;
  bad_address[kRawPkhAddressLength / 2] ^= 0x5e;
  EXPECT_FALSE(PkhAddress::IsValidAddress(bad_address));
}

TEST(WalletAddressTest, KnownPkhAddress) {
  // This example was taken from bitcoin.it's example address.
  // Note that the key is compressed.
  constexpr bool kCompressed = true;
  const std::vector<uint8_t> priv_key_data = HexDecode(
      "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
  auto priv_key = EccPrivateKey::LoadAsScalar(priv_key_data);
  ASSERT_TRUE(priv_key);

  const PkhAddress address(kMainNetwork, *priv_key, kCompressed);
  EXPECT_TRUE(address.IsSet());
  EXPECT_EQ(kMainNetwork, address.network_id());

  const std::string key_hash = HexEncode(address.key_hash());
  EXPECT_EQ(key_hash, "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");

  const std::string checksum = HexEncode(address.GenerateChecksum());
  EXPECT_EQ(checksum, "c7f18fe8");

  const std::string hex_address = HexEncode(address.Serialize());
  EXPECT_EQ(hex_address, "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8");

  const std::string b58_address = address.SerializeBase58();
  EXPECT_EQ(b58_address, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
}

TEST(WalletAddressTest, ParsePkhAddressRaw) {
  PkhAddress address;
  EXPECT_FALSE(address.IsSet());

  const std::vector<uint8_t> address_raw =
      HexDecode("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8");
  ASSERT_TRUE(address.Parse(address_raw));

  EXPECT_TRUE(address.IsSet());
  EXPECT_EQ(kMainNetwork, address.network_id());

  const std::string key_hash = HexEncode(address.key_hash());
  EXPECT_EQ(key_hash, "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");

  const std::string checksum = HexEncode(address.GenerateChecksum());
  EXPECT_EQ(checksum, "c7f18fe8");

  const std::string hex_address = HexEncode(address.Serialize());
  EXPECT_EQ(hex_address, "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8");

  const std::string b58_address = address.SerializeBase58();
  EXPECT_EQ(b58_address, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
}

TEST(WalletAddressTest, ParsePkhAddressBase58) {
  PkhAddress address;
  EXPECT_FALSE(address.IsSet());
  ASSERT_TRUE(address.ParseBase58("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"));

  EXPECT_TRUE(address.IsSet());
  EXPECT_EQ(kMainNetwork, address.network_id());

  const std::string key_hash = HexEncode(address.key_hash());
  EXPECT_EQ(key_hash, "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");

  const std::string checksum = HexEncode(address.GenerateChecksum());
  EXPECT_EQ(checksum, "c7f18fe8");

  const std::string hex_address = HexEncode(address.Serialize());
  EXPECT_EQ(hex_address, "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8");

  const std::string b58_address = address.SerializeBase58();
  EXPECT_EQ(b58_address, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
}
}  // namespace test
}  // namespace wallet
}  // namespace btc
