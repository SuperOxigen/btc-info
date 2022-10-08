// Bitcoin Info - Cryptography - OpenSSL ECC Key
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CRYPTO_OPENSSL_ECC_KEY_HPP_
#define _BTC_CRYPTO_OPENSSL_ECC_KEY_HPP_

#ifndef _BTC_CRYPTO_ECC_KEY_INTERNAL_
#  error Header should only be included internally
#endif  // _BTC_CRYPTO_ECC_KEY_INTERNAL_

#include <memory>
#include <vector>

#include <openssl/ec.h>

#include "btc/cc/attr.h"
#include "btc/cc/base.h"
#include "btc/cc/classy.hpp"
#include "btc/crypto/ecc_key.hpp"
#include "btc/mem/auto_ptr.hpp"

namespace btc {
namespace crypto {
namespace internal {
using EcKeyPointer = btc::mem::AutoPointer<EC_KEY, EC_KEY_free>;

class EccNativeKey {
public:
  BTC_DISALLOW_COPY_AND_MOVE(EccNativeKey);
  ~EccNativeKey() {}

  static std::unique_ptr<EccNativeKey> New() {
    std::unique_ptr<EccNativeKey> key(new EccNativeKey());
    if (!key->InitNew()) {
      key.reset();
    }
    return key;
  }
  static std::unique_ptr<EccNativeKey> LoadSubjectPublicKeyInfo(
      const std::vector<uint8_t> &key_info) {
    std::unique_ptr<EccNativeKey> key(new EccNativeKey());
    if (!key->InitFromSubjectPublicKeyInfo(key_info)) {
      key.reset();
    }
    return key;
  }
  static std::unique_ptr<EccNativeKey> LoadPrivateKeyInfo(
      const std::vector<uint8_t> &key_info) {
    std::unique_ptr<EccNativeKey> key(new EccNativeKey());
    if (!key->InitFromPrivateKeyInfo(key_info)) {
      key.reset();
    }
    return key;
  }
  static std::unique_ptr<EccNativeKey> LoadAsPoint(
      const std::vector<uint8_t> &ecc_point) {
    std::unique_ptr<EccNativeKey> key(new EccNativeKey());
    if (!key->InitFromPoint(ecc_point)) {
      key.reset();
    }
    return key;
  }
  static std::unique_ptr<EccNativeKey> LoadAsScalar(
      const std::vector<uint8_t> &ecc_scalar) {
    std::unique_ptr<EccNativeKey> key(new EccNativeKey());
    if (!key->InitFromScalar(ecc_scalar)) {
      key.reset();
    }
    return key;
  }

  EC_KEY *key() { return _key.Get(); }
  const EC_KEY *key() const { return _key.Get(); }
  bool is_private() const { return _is_private; }

  std::vector<uint8_t> SerializeSubjectPublicKeyInfo() const;
  std::vector<uint8_t> SerializePrivateKeyInfo() const;
  std::vector<uint8_t> SerializeAsPublicPoint(bool compress) const;
  std::vector<uint8_t> SerializeAsPrivateScalar() const;

  bool VerifySignature(
      const uint8_t *data, size_t data_size,
      const std::vector<uint8_t> &signature) const;
  std::vector<uint8_t> GenerateSignature(
      const uint8_t *data, size_t data_size) const;

private:
  EccNativeKey() {}

  bool InitNew();
  bool InitFromSubjectPublicKeyInfo(const std::vector<uint8_t> &key_info);
  bool InitFromPrivateKeyInfo(const std::vector<uint8_t> &key_info);
  bool InitFromPoint(const std::vector<uint8_t> &ecc_point);
  bool InitFromScalar(const std::vector<uint8_t> &ecc_scalar);

  EcKeyPointer _key = nullptr;
  bool _is_private = false;
};  // class EccNativeKey
}  // namespace internal
}  // namespace crypto
}  // namespace btc

#endif  // _BTC_CRYPTO_OPENSSL_ECC_KEY_HPP_
