// Bitcoin Info - Cryptography - OpenSSL Digest Algorithm
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "btc/cc/debug.h"
#include "btc/crypto/digest.hpp"
#include "btc/log.h"

namespace btc {
namespace crypto {
namespace {
const uint8_t kSpareByte = 0;
const uint8_t *const kNullByteFill = &kSpareByte;

using digester_t = uint8_t *(*) (const uint8_t *, size_t, uint8_t *);

// Single pass digesters.

template<digester_t Digester>
bool DigestImpl(const uint8_t *data, size_t data_size, uint8_t *digest) {
  DASSERT(digest != nullptr);
  if (data == nullptr && data_size > 0) return false;
  const uint8_t *res = Digester(data ? data : kNullByteFill, data_size, digest);
  return res != nullptr;
}

template<digester_t Digester>
bool DigestImpl(const std::string &data, uint8_t *digest) {
  DASSERT(digest != nullptr);
  const uint8_t *res = Digester(
      data.empty() ? kNullByteFill
                   : reinterpret_cast<const uint8_t *>(data.data()),
      data.size(), digest);
  return res != nullptr;
}

template<digester_t Digester>
bool DigestImpl(const std::vector<uint8_t> &data, uint8_t *digest) {
  DASSERT(digest != nullptr);
  const uint8_t *res =
      Digester(data.empty() ? kNullByteFill : data.data(), data.size(), digest);
  return res != nullptr;
}

template<digester_t Digester, size_t kDigestLength>
std::vector<uint8_t> DigestImpl(const uint8_t *data, size_t data_size) {
  if (data == nullptr && data_size > 0) return {};
  std::vector<uint8_t> digest(kDigestLength);
  const uint8_t *res =
      Digester(data ? data : kNullByteFill, data_size, digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}

template<digester_t Digester, size_t kDigestLength>
std::vector<uint8_t> DigestImpl(const std::string &data) {
  std::vector<uint8_t> digest(kDigestLength);
  const uint8_t *res = Digester(
      data.empty() ? kNullByteFill
                   : reinterpret_cast<const uint8_t *>(data.data()),
      data.size(), digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}

template<digester_t Digester, size_t kDigestLength>
std::vector<uint8_t> DigestImpl(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> digest(kDigestLength);
  const uint8_t *res = Digester(
      data.empty() ? kNullByteFill : data.data(), data.size(), digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}

// Double pass digesters.

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester>
bool DoubleDigestImpl(const uint8_t *data, size_t data_size, uint8_t *digest) {
  DASSERT(digest != nullptr);
  if (data == nullptr && data_size > 0) return false;
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res =
      FirstDigester(data ? data : kNullByteFill, data_size, first_digest);
  if (res == nullptr) return false;
  res = SecondDigester(first_digest, kFirstDigestLength, digest);
  return res != nullptr;
}

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester>
bool DoubleDigestImpl(const std::string &data, uint8_t *digest) {
  DASSERT(digest != nullptr);
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res = FirstDigester(
      data.empty() ? kNullByteFill
                   : reinterpret_cast<const uint8_t *>(data.data()),
      data.size(), first_digest);
  if (res == nullptr) return false;
  res = SecondDigester(first_digest, kFirstDigestLength, digest);
  return res != nullptr;
}

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester>
bool DoubleDigestImpl(const std::vector<uint8_t> &data, uint8_t *digest) {
  DASSERT(digest != nullptr);
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res = FirstDigester(
      data.empty() ? kNullByteFill : data.data(), data.size(), first_digest);
  if (res == nullptr) return false;
  res = SecondDigester(first_digest, kFirstDigestLength, digest);
  return res != nullptr;
}

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester, size_t kSecondDigestLength>
std::vector<uint8_t> DoubleDigestImpl(const uint8_t *data, size_t data_size) {
  if (data == nullptr && data_size > 0) return {};
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res =
      FirstDigester(data ? data : kNullByteFill, data_size, first_digest);
  if (res == nullptr) return {};
  std::vector<uint8_t> digest(kSecondDigestLength);
  res = SecondDigester(first_digest, kFirstDigestLength, digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester, size_t kSecondDigestLength>
std::vector<uint8_t> DoubleDigestImpl(const std::string &data) {
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res = FirstDigester(
      data.empty() ? kNullByteFill
                   : reinterpret_cast<const uint8_t *>(data.data()),
      data.size(), first_digest);
  if (res == nullptr) return {};
  std::vector<uint8_t> digest(kSecondDigestLength);
  res = SecondDigester(first_digest, kFirstDigestLength, digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}

template<
    digester_t FirstDigester, size_t kFirstDigestLength,
    digester_t SecondDigester, size_t kSecondDigestLength>
std::vector<uint8_t> DoubleDigestImpl(const std::vector<uint8_t> &data) {
  uint8_t first_digest[kFirstDigestLength];
  const uint8_t *res = FirstDigester(
      data.empty() ? kNullByteFill : data.data(), data.size(), first_digest);
  if (res == nullptr) return {};
  std::vector<uint8_t> digest(kSecondDigestLength);
  res = SecondDigester(first_digest, kFirstDigestLength, digest.data());
  if (res == nullptr) digest.clear();
  return digest;
}
}  // namespace

// SHA-256

bool Sha256(const uint8_t *data, size_t data_size, uint8_t *digest) {
  return DigestImpl<SHA256>(data, data_size, digest);
}

bool Sha256(const std::string &data, uint8_t *digest) {
  return DigestImpl<SHA256>(data, digest);
}
bool Sha256(const std::vector<uint8_t> &data, uint8_t *digest) {
  return DigestImpl<SHA256>(data, digest);
}

std::vector<uint8_t> Sha256(const uint8_t *data, size_t data_size) {
  return DigestImpl<SHA256, kSha256DigestLength>(data, data_size);
}

std::vector<uint8_t> Sha256(const std::string &data) {
  return DigestImpl<SHA256, kSha256DigestLength>(data);
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t> &data) {
  return DigestImpl<SHA256, kSha256DigestLength>(data);
}

// SHA-256-SHA-256

bool Sha256Sha256(const uint8_t *data, size_t data_size, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, SHA256>(
      data, data_size, digest);
}

bool Sha256Sha256(const std::string &data, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, SHA256>(data, digest);
}
bool Sha256Sha256(const std::vector<uint8_t> &data, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, SHA256>(data, digest);
}

std::vector<uint8_t> Sha256Sha256(const uint8_t *data, size_t data_size) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, SHA256, kSha256DigestLength>(
      data, data_size);
}

std::vector<uint8_t> Sha256Sha256(const std::string &data) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, SHA256, kSha256DigestLength>(data);
}

std::vector<uint8_t> Sha256Sha256(const std::vector<uint8_t> &data) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, SHA256, kSha256DigestLength>(data);
}

// SHA-256-RIPEMD-160

bool Sha256RipeMd160(const uint8_t *data, size_t data_size, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, RIPEMD160>(
      data, data_size, digest);
}

bool Sha256RipeMd160(const std::string &data, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, RIPEMD160>(data, digest);
}
bool Sha256RipeMd160(const std::vector<uint8_t> &data, uint8_t *digest) {
  return DoubleDigestImpl<SHA256, kSha256DigestLength, RIPEMD160>(data, digest);
}

std::vector<uint8_t> Sha256RipeMd160(const uint8_t *data, size_t data_size) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, RIPEMD160, kRipeMd160DigestLength>(
      data, data_size);
}

std::vector<uint8_t> Sha256RipeMd160(const std::string &data) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, RIPEMD160, kRipeMd160DigestLength>(data);
}

std::vector<uint8_t> Sha256RipeMd160(const std::vector<uint8_t> &data) {
  return DoubleDigestImpl<
      SHA256, kSha256DigestLength, RIPEMD160, kRipeMd160DigestLength>(data);
}
}  // namespace crypto
}  // namespace btc
