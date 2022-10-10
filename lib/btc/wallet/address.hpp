// Bitcoin Info - Wallet - Address
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_WALLET_ADDRESS_HPP_
#define _BTC_WALLET_ADDRESS_HPP_

#include <string>
#include <vector>

#include "btc/cc/base.h"
#include "btc/cc/classy.hpp"
#include "btc/crypto/ecc_key.hpp"

namespace btc {
namespace wallet {
using NetworkId = uint8_t;
static constexpr NetworkId kMainNetwork = 0x00;
static constexpr NetworkId kTestNetwork = 0x6f;
static constexpr NetworkId kNamecoinNetwork = 0x34;

static constexpr size_t kRawPkhAddressLength = 25;

// P2PKH Bitcoin addresses have the following format:
//  network ID (1 byte)
//  key hash   (20 bytes) = RIPEMD-160(SHA-256(pub_key_point))
//  checksum   (4 bytes)  = First 4 bytes of
//                            SHA-256(SHA-256(network ID || key hash))
//             (25 bytes total)
class PkhAddress {
public:
  BTC_DEFAULT_COPY_AND_MOVE(PkhAddress);
  static bool IsValidAddress(const std::vector<uint8_t> &address);
  static bool IsValidAddressBase58(const std::string &address);

  PkhAddress() {}
  PkhAddress(
      NetworkId network, const ::btc::crypto::EccPublicKey &pub_key,
      bool compress = false);

  bool Parse(const std::vector<uint8_t> &address_raw);
  bool ParseBase58(const std::string &address_b58);

  bool IsSet() const { return !_key_hash.empty(); }
  explicit operator bool() { return IsSet(); }

  NetworkId network_id() const { return _network_id; }
  const std::vector<uint8_t> &key_hash() const { return _key_hash; }

  std::vector<uint8_t> Serialize() const;
  std::string SerializeBase58() const;

  std::vector<uint8_t> GenerateChecksum() const;

private:
  NetworkId _network_id = kMainNetwork;
  std::vector<uint8_t> _key_hash = {};
};  // class PkhAddress
}  // namespace wallet
}  // namespace btc

#endif  // _BTC_WALLET_ADDRESS_HPP_
