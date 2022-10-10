// Bitcoin Info - Wallet - Address
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <endian.h>
#include <string.h>

#include <algorithm>

#include "btc/cc/debug.h"
#include "btc/crypto/digest.hpp"
#include "btc/crypto/digester.hpp"
#include "btc/encode/base58.hpp"
#include "btc/log.h"
#include "btc/wallet/address.hpp"

namespace btc {
namespace wallet {
using ::btc::crypto::Digester;
using ::btc::crypto::EccPublicKey;
using ::btc::crypto::kSha256DigestLength;
using ::btc::crypto::kSha256Sha256;
using ::btc::crypto::Sha256RipeMd160;
using ::btc::crypto::Sha256Sha256;
using ::btc::encode::Base58Decode;
using ::btc::encode::Base58Encode;
using ::btc::encode::IsBase58String;
namespace {
static constexpr size_t kKeyHashLength = 20;
constexpr size_t kChecksumOffset = 1 + kKeyHashLength;
constexpr size_t kChecksumLength = 4;
using checksum_t = uint8_t[kChecksumLength];

bool CalculateChecksum(
    NetworkId network_id, const std::vector<uint8_t> &key_hash,
    uint8_t *checksum) {
  DASSERT(key_hash.size() == kKeyHashLength);
  DASSERT(checksum != nullptr);
  auto digester = Digester::New(kSha256Sha256);
  if (!digester) {
    LOG_ERROR("Failed to create a SHA-256-SHA-256 digester");
    return false;
  }
  if (!digester->Update(network_id) || !digester->Update(key_hash)) {
    LOG_ERROR("Failed to update digest for checksum");
    return false;
  }
  uint8_t digest[kSha256DigestLength];
  if (!digester->Finalize(digest)) {
    LOG_ERROR("Failed to finalize checksum");
    return false;
  }
  memcpy(checksum, digest, kChecksumLength);
  return true;
}

std::vector<uint8_t> HashPublicKey(const EccPublicKey &pub_key, bool compress) {
  const std::vector<uint8_t> serialized_key =
      pub_key.SerializeAsPublicPoint(compress);
  if (serialized_key.empty()) {
    LOG_ERROR("Failed to serialize public key");
    return {};
  }
  return Sha256RipeMd160(serialized_key);
}
}  // namespace

// static
bool PkhAddress::IsValidAddress(const std::vector<uint8_t> &address) {
  if (address.size() != kRawPkhAddressLength) {
    LOG_DEBUG(
        "Invalid address length: expected = %zu, actual = %zu",
        kRawPkhAddressLength, address.size());
    return false;
  }
  uint8_t checksum[kSha256DigestLength];
  if (!Sha256Sha256(
          address.data(), kRawPkhAddressLength - kChecksumLength, checksum)) {
    LOG_ERROR("Failed to generate checksum");
    return false;
  }
  const bool valid_checksum = std::equal(
      checksum, checksum + kChecksumLength, address.begin() + kChecksumOffset);
  if (!valid_checksum) {
    LOG_DEBUG("Bad checksum");
    return false;
  }
  return true;
}

// static
bool PkhAddress::IsValidAddressBase58(const std::string &address) {
  if (address.empty()) {
    LOG_DEBUG("Base58 address is empty");
    return false;
  }
  if (!IsBase58String(address)) {
    LOG_DEBUG("Address is not base58 encoded");
    return false;
  }
  return IsValidAddress(Base58Decode(address));
}

PkhAddress::PkhAddress(
    NetworkId network, const EccPublicKey &pub_key, bool compress):
    _network_id(network), _key_hash(HashPublicKey(pub_key, compress)) {
  DASSERT(!_key_hash.empty());
}

bool PkhAddress::Parse(const std::vector<uint8_t> &address_raw) {
  if (!IsValidAddress(address_raw)) {
    LOG_ERROR("Invalid address");
    return false;
  }
  _network_id = address_raw[0];
  const auto key_hash_begin = address_raw.begin() + 1;
  _key_hash.assign(key_hash_begin, key_hash_begin + kKeyHashLength);
  return true;
}

bool PkhAddress::ParseBase58(const std::string &address_b58) {
  if (address_b58.empty()) {
    LOG_DEBUG("Base58 address is empty");
    return false;
  }
  if (!IsBase58String(address_b58)) {
    LOG_DEBUG("Address is not base58 encoded");
    return false;
  }
  return Parse(Base58Decode(address_b58));
}

std::vector<uint8_t> PkhAddress::Serialize() const {
  if (!IsSet()) return {};
  std::vector<uint8_t> address;
  address.reserve(kRawPkhAddressLength);
  address.push_back(_network_id);
  address.insert(address.end(), _key_hash.begin(), _key_hash.end());
  address.insert(address.end(), kChecksumLength, 0);
  DASSERT(address.size() == kRawPkhAddressLength);
  if (!CalculateChecksum(_network_id, _key_hash, &address[kChecksumOffset])) {
    LOG_ERROR("Failed to calculate checksum");
    return {};
  }
  return address;
}

std::string PkhAddress::SerializeBase58() const {
  if (!IsSet()) return "";
  const std::vector<uint8_t> address_raw = Serialize();
  if (address_raw.empty()) {
    LOG_ERROR("Failed to serialize key");
    return "";
  }
  return Base58Encode(address_raw);
}

std::vector<uint8_t> PkhAddress::GenerateChecksum() const {
  if (!IsSet()) return {};
  std::vector<uint8_t> checksum(kChecksumLength, 0);
  if (!CalculateChecksum(_network_id, _key_hash, checksum.data())) {
    LOG_ERROR("Failed to calculate checksum");
    return {};
  }
  return checksum;
}
}  // namespace wallet
}  // namespace btc
