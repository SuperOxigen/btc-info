// Bitcoin Info - Cryptography - OpenSSL Digester
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <utility>

#include "btc/cc/debug.h"
#include "btc/crypto/digest.hpp"
#include "btc/crypto/digester.hpp"
#include "btc/log.h"

#define _BTC_CRYPTO_DIGESTER_INTERNAL_
#include "btc/crypto/digester.openssl.hpp"
#undef _BTC_CRYPTO_DIGESTER_INTERNAL_

namespace btc {
namespace crypto {
namespace internal {
bool NativeDigester::Init() {
  // Create the CTXs.
  _ctx = EVP_MD_CTX_new();
  if (!_ctx) {
    LOG_ERROR("Failed to allocate main CTX");
    return false;
  }
  _backup_ctx = EVP_MD_CTX_new();
  if (!_backup_ctx) {
    LOG_ERROR("Failed to allocate backup CTX");
    return false;
  }
  // Initialize main.
  if (!EVP_DigestInit(_ctx.Get(), EVP_sha256())) {
    LOG_ERROR("Failed to initialize main CTX as SHA-256");
    return false;
  }
  _ready = true;
  return true;
}

bool NativeDigester::Save() {
  if (!EVP_MD_CTX_copy(_backup_ctx.Get(), _ctx.Get())) {
    LOG_ERROR("Failed to backup CTX");
    _has_backup = false;
    return false;
  }
  _has_backup = true;
  return true;
}

bool NativeDigester::Restore() {
  if (!_has_backup) {
    LOG_ERROR("No backup CTX to restore from");
    return false;
  }
  if (!EVP_MD_CTX_copy(_ctx.Get(), _backup_ctx.Get())) {
    LOG_ERROR("Failed to restore CTX");
    return false;
  }
  _ready = true;
  _has_backup = false;
  return true;
}

bool NativeDigester::Reset() {
  if (!EVP_DigestInit(_ctx.Get(), EVP_sha256())) {
    LOG_ERROR("Failed to reset");
    _ready = false;
    _has_backup = false;
    return false;
  }
  _ready = true;
  _has_backup = false;
  return true;
}

bool NativeDigester::Update(const uint8_t *data, size_t data_size) {
  DASSERT(data != nullptr);
  if (!_ready && _has_backup) {
    if (!Restore()) return false;
  } else if (!_ready) {
    if (!Reset()) return false;
  }
  if (data_size == 0) {
    return true;
  }
  if (!EVP_DigestUpdate(_ctx.Get(), data, data_size)) {
    LOG_ERROR("Failed to update: data_size = %zu", data_size);
    _ready = false;
    return false;
  }
  return true;
}

bool NativeDigester::Finalize(uint8_t *digest) {
  DASSERT(digest != nullptr);
  if (!_ready && _has_backup) {
    if (!Restore()) return false;
  } else if (!_ready) {
    if (!Reset()) return false;
  } else {
    if (!Save()) {
      LOG_WARN("Failed to save CTX state");
    }
  }
  _ready = false;
  if (!EVP_DigestFinal(_ctx.Get(), digest, nullptr)) {
    LOG_ERROR("Failed to finalize digest");
    return false;
  }
  return true;
}
}  // namespace internal
using internal::NativeDigester;
namespace {
using sha_256_digest_t = uint8_t[kSha256DigestLength];

bool IsSupportedDigestAlgorithm(DigestAlgorithm algorithm) {
  switch (algorithm) {
    case kSha256:
    case kSha256Sha256:
    case kSha256RipeMd160:
      return true;
    case kRipeMd160:
    case kUnknownDigestAlgorithm:
      return false;
  }
  LOG_ERROR("Unknown digest algorithm: %d", algorithm);
  return false;
}

size_t GetDigestLength(DigestAlgorithm algorithm) {
  switch (algorithm) {
    case kSha256:
    case kSha256Sha256:
      return kSha256DigestLength;
    case kSha256RipeMd160:
      return kRipeMd160DigestLength;
    case kRipeMd160:
    case kUnknownDigestAlgorithm:
      return 0;
  }
  LOG_ERROR("Unknown digest algorithm: %d", algorithm);
  return 0;
}
}  // namespace

Digester::Digester(
    DigestAlgorithm algorithm,
    std::unique_ptr<NativeDigester> &&native_digester):
    _algorithm(algorithm),
    _digest_length(GetDigestLength(algorithm)),
    _digester(std::move(native_digester)) {
  DASSERT(_digest_length > 0);
  DASSERT(_digester);
}

Digester::~Digester() {}

// static
std::unique_ptr<Digester> Digester::New(DigestAlgorithm algorithm) {
  if (!IsSupportedDigestAlgorithm(algorithm)) {
    LOG_ERROR("Unsupport digest algorithm: %d", algorithm);
    return nullptr;
  }
  auto native_digester = NativeDigester::New();
  if (!native_digester) {
    LOG_ERROR("Failed to initialize native digester");
    return nullptr;
  }
  return std::unique_ptr<Digester>(
      new Digester(algorithm, std::move(native_digester)));
}

void Digester::Reset() {
  _digester->Reset();
  _byte_count = 0;
}

bool Digester::Update(uint8_t datum) {
  if (!_digester->Update(&datum, 1)) {
    return false;
  }
  _byte_count++;
  return true;
}

bool Digester::Update(const uint8_t *data, size_t data_size) {
  if (data_size == 0) return true;
  if (data == nullptr) {
    LOG_ERROR("Input |data| is null");
    return false;
  }
  if (!_digester->Update(data, data_size)) {
    return false;
  }
  _byte_count += data_size;
  return true;
}

bool Digester::Update(const std::string &data) {
  if (data.empty()) return true;
  if (!_digester->Update(
          reinterpret_cast<const uint8_t *>(data.data()), data.size())) {
    return false;
  }
  _byte_count += data.size();
  return true;
}

bool Digester::Update(const std::vector<uint8_t> &data) {
  if (data.empty()) return true;
  if (!_digester->Update(data.data(), data.size())) {
    return false;
  }
  _byte_count += data.size();
  return true;
}

bool Digester::Finalize(uint8_t *digest) {
  if (digest == nullptr) {
    LOG_ERROR("Output |digest| is null");
    return false;
  }
  if (_algorithm == kSha256) {
    return _digester->Finalize(digest);
  }
  sha_256_digest_t intermediate_digest;
  if (!_digester->Finalize(intermediate_digest)) {
    LOG_ERROR("Failed to generate intermediate digest");
    return false;
  }
  if (_algorithm == kSha256Sha256) {
    return Sha256(intermediate_digest, kSha256DigestLength, digest);
  }
  DASSERT(_algorithm == kSha256RipeMd160);
  return RipeMd160(intermediate_digest, kSha256DigestLength, digest);
}

std::vector<uint8_t> Digester::Finalize() {
  std::vector<uint8_t> digest(kSha256DigestLength);
  if (!_digester->Finalize(digest.data())) {
    LOG_ERROR("Failed to generate initialize digest");
    return {};
  }
  if (_algorithm == kSha256) {
    return digest;
  }
  if (_algorithm == kSha256Sha256) {
    return Sha256(digest);
  }
  DASSERT(_algorithm == kSha256RipeMd160);
  return RipeMd160(digest);
}
}  // namespace crypto
}  // namespace btc
