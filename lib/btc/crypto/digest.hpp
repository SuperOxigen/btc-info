// Bitcoin Info - Cryptography - Digest Algorithm
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CRYPTO_HASH_HPP_
#define _BTC_CRYPTO_HASH_HPP_

#include <string>
#include <vector>

#include "btc/cc/attr.h"
#include "btc/cc/base.h"

namespace btc {
namespace crypto {
enum DigestAlgorithm {
  kUnknownDigestAlgorithm = 0,
  // Primative Algorithms
  // SHA2 Family
  kSha256 = 2001256,
  // RIPE MD Family
  kRipeMd160 = 1992160,
  // Compound Algorithms
  // SHA-256(SHA-256(x))
  kSha256Sha256 = 2001256256,
  // RIPEMD-160(SHA-256(x))
  kSha256RipeMd160 = 1992160256,
};  // enum DigestAlgorithm

const char *DigestAlgorithmToString(DigestAlgorithm algorithm)
    __RETURN_NOT_NULL;

// Generic digests.
std::vector<uint8_t> Digest(
    DigestAlgorithm algorithm, const uint8_t *data, size_t data_size);
std::vector<uint8_t> Digest(DigestAlgorithm algorithm, const std::string &data);
std::vector<uint8_t> Digest(
    DigestAlgorithm algorithm, const std::vector<uint8_t> &data);

// SHA-256

constexpr size_t kSha256DigestLength = 32;

bool Sha256(const uint8_t *data, size_t data_size, uint8_t *digest)
    __NOT_NULL(3);
bool Sha256(const std::string &data, uint8_t *digest) __NOT_NULL(2);
bool Sha256(const std::vector<uint8_t> &data, uint8_t *digest) __NOT_NULL(2);
std::vector<uint8_t> Sha256(const uint8_t *data, size_t data_size);
std::vector<uint8_t> Sha256(const std::string &data);
std::vector<uint8_t> Sha256(const std::vector<uint8_t> &data);

// SHA-256-SHA-256

bool Sha256Sha256(const uint8_t *data, size_t data_size, uint8_t *digest)
    __NOT_NULL(3);
bool Sha256Sha256(const std::string &data, uint8_t *digest) __NOT_NULL(2);
bool Sha256Sha256(const std::vector<uint8_t> &data, uint8_t *digest)
    __NOT_NULL(2);
std::vector<uint8_t> Sha256Sha256(const uint8_t *data, size_t data_size);
std::vector<uint8_t> Sha256Sha256(const std::string &data);
std::vector<uint8_t> Sha256Sha256(const std::vector<uint8_t> &data);

// RIPEMD-160

constexpr size_t kRipeMd160DigestLength = 20;

bool RipeMd160(const uint8_t *data, size_t data_size, uint8_t *digest)
    __NOT_NULL(3);
bool RipeMd160(const std::string &data, uint8_t *digest) __NOT_NULL(2);
bool RipeMd160(const std::vector<uint8_t> &data, uint8_t *digest) __NOT_NULL(2);
std::vector<uint8_t> RipeMd160(const uint8_t *data, size_t data_size);
std::vector<uint8_t> RipeMd160(const std::string &data);
std::vector<uint8_t> RipeMd160(const std::vector<uint8_t> &data);

// SHA-256-RIPEMD-160

bool Sha256RipeMd160(const uint8_t *data, size_t data_size, uint8_t *digest)
    __NOT_NULL(3);
bool Sha256RipeMd160(const std::string &data, uint8_t *digest) __NOT_NULL(2);
bool Sha256RipeMd160(const std::vector<uint8_t> &data, uint8_t *digest)
    __NOT_NULL(2);
std::vector<uint8_t> Sha256RipeMd160(const uint8_t *data, size_t data_size);
std::vector<uint8_t> Sha256RipeMd160(const std::string &data);
std::vector<uint8_t> Sha256RipeMd160(const std::vector<uint8_t> &data);
}  // namespace crypto
}  // namespace btc

#endif  // _BTC_CRYPTO_HASH_HPP_
