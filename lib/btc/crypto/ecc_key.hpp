// Bitcoin Info - Cryptography - ECC Key
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CRYPTO_ECC_KEY_HPP_
#define _BTC_CRYPTO_ECC_KEY_HPP_

#include <memory>
#include <string>
#include <vector>

#include "btc/cc/base.h"
#include "btc/cc/classy.hpp"

namespace btc {
namespace crypto {

namespace internal {
class EccNativeKey;
}  // namespace internal

// secp256k1
class EccPublicKey {
public:
  BTC_DISALLOW_COPY_AND_MOVE(EccPublicKey);
  ~EccPublicKey();

  static std::unique_ptr<EccPublicKey> LoadSubjectPublicKeyInfo(
      const std::vector<uint8_t> &key_info);
  static std::unique_ptr<EccPublicKey> LoadPrivateKeyInfo(
      const std::vector<uint8_t> &key_info);
  static std::unique_ptr<EccPublicKey> LoadAsPoint(
      const std::vector<uint8_t> &ecc_point);
  static std::unique_ptr<EccPublicKey> LoadAsScalar(
      const std::vector<uint8_t> &ecc_scalar);

  std::vector<uint8_t> SerializeSubjectPublicKeyInfo() const;
  std::vector<uint8_t> SerializeAsPublicPoint(bool compress) const;

  // Signature verification.  ECDSA, with SHA-256-SHA-256.
  bool VerifySignature(
      const std::string &data, const std::vector<uint8_t> &signature) const;
  bool VerifySignature(
      const std::vector<uint8_t> &data,
      const std::vector<uint8_t> &signature) const;
  bool VerifySignature(
      const uint8_t *data, size_t data_size,
      const std::vector<uint8_t> &signature) const;

  const internal::EccNativeKey *native_key() const { return _key.get(); }
  internal::EccNativeKey *native_key() { return _key.get(); }

protected:
  EccPublicKey(std::unique_ptr<internal::EccNativeKey> &&key);

  std::unique_ptr<internal::EccNativeKey> _key;
};  // class EccPublicKey

class EccPrivateKey: public EccPublicKey {
public:
  BTC_DISALLOW_COPY_AND_MOVE(EccPrivateKey);
  ~EccPrivateKey();

  static std::unique_ptr<EccPrivateKey> New();

  static std::unique_ptr<EccPrivateKey> LoadPrivateKeyInfo(
      const std::vector<uint8_t> &key_info);
  static std::unique_ptr<EccPrivateKey> LoadAsScalar(
      const std::vector<uint8_t> &ecc_scalar);

  std::vector<uint8_t> SerializePrivateKeyInfo() const;
  std::vector<uint8_t> SerializeAsPrivateScalar() const;

  // Signature generation.  ECDSA.
  // For ECC, signatures are DER encoded ECDSA-Sig-Value.
  std::vector<uint8_t> GenerateSignature(const std::string &data) const;
  std::vector<uint8_t> GenerateSignature(
      const std::vector<uint8_t> &data) const;
  std::vector<uint8_t> GenerateSignature(
      const uint8_t *data, size_t data_size) const;

private:
  EccPrivateKey(std::unique_ptr<internal::EccNativeKey> &&key);
};  // class EccPrivateKey
}  // namespace crypto
}  // namespace btc

#endif  // _BTC_CRYPTO_ECC_KEY_HPP_
