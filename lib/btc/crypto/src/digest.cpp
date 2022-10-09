// Bitcoin Info - Cryptography - Digest Algorithm
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include "btc/crypto/digest.hpp"
#include "btc/log.h"

namespace btc {
namespace crypto {
const char *DigestAlgorithmToString(DigestAlgorithm algorithm) {
  switch (algorithm) {
    case kSha256:
      return "SHA-256";
    case kRipeMd160:
      return "RIPEMD-160";
    case kSha256Sha256:
      return "SHA-256-SHA-256";
    case kSha256RipeMd160:
      return "SHA-256-RIPEMD-160";
    case kUnknownDigestAlgorithm:
      return "<unknown>";
  }
  LOG_ERROR("Unknown digest algorithm: %d", algorithm);
  return "<error>";
}

std::vector<uint8_t> Digest(
    DigestAlgorithm algorithm, const uint8_t *data, size_t data_size) {
  switch (algorithm) {
    case kSha256:
      return Sha256(data, data_size);
    case kRipeMd160:
      return RipeMd160(data, data_size);
    case kSha256Sha256:
      return Sha256Sha256(data, data_size);
    case kSha256RipeMd160:
      return Sha256RipeMd160(data, data_size);
    case kUnknownDigestAlgorithm:
      break;
  }
  LOG_ERROR("Unsupported digest algorithm: %d", algorithm);
  return {};
}

std::vector<uint8_t> Digest(
    DigestAlgorithm algorithm, const std::string &data) {
  switch (algorithm) {
    case kSha256:
      return Sha256(data);
    case kRipeMd160:
      return RipeMd160(data);
    case kSha256Sha256:
      return Sha256Sha256(data);
    case kSha256RipeMd160:
      return Sha256RipeMd160(data);
    case kUnknownDigestAlgorithm:
      break;
  }
  LOG_ERROR("Unsupported digest algorithm: %d", algorithm);
  return {};
}

std::vector<uint8_t> Digest(
    DigestAlgorithm algorithm, const std::vector<uint8_t> &data) {
  switch (algorithm) {
    case kSha256:
      return Sha256(data);
    case kRipeMd160:
      return RipeMd160(data);
    case kSha256Sha256:
      return Sha256Sha256(data);
    case kSha256RipeMd160:
      return Sha256RipeMd160(data);
    case kUnknownDigestAlgorithm:
      break;
  }
  LOG_ERROR("Unsupported digest algorithm: %d", algorithm);
  return {};
}
}  // namespace crypto
}  // namespace btc
