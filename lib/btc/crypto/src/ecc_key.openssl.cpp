// Bitcoin Info - Cryptography - OpenSSL ECC Key
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <limits>
#include <utility>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "btc/cc/debug.h"
#include "btc/crypto/digest.hpp"
#include "btc/crypto/ecc_key.hpp"
#include "btc/log.h"
#include "btc/mem/auto_ptr.hpp"

#define _BTC_CRYPTO_ECC_KEY_INTERNAL_
#include "btc/crypto/ecc_key.openssl.hpp"
#undef _BTC_CRYPTO_ECC_KEY_INTERNAL_

namespace btc {
namespace crypto {
namespace internal {
using ::btc::mem::AutoPointer;
using EvpKeyPointer = AutoPointer<EVP_PKEY, EVP_PKEY_free>;
using BnCtxPointer = AutoPointer<BN_CTX, BN_CTX_free>;
using EcPointPointer = AutoPointer<EC_POINT, EC_POINT_free>;
namespace {
constexpr int kSecp256k1Id = NID_secp256k1;

constexpr size_t kMaxInt = static_cast<size_t>(std::numeric_limits<int>::max());

bool CheckEcKey(EC_KEY *key) {
  return EC_KEY_check_key(key) == 1;
}

void SetEcKeyFlags(EC_KEY *key) {
  DASSERT(key != nullptr);
  EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
  EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
}

constexpr point_conversion_form_t OpenSslPointConversionForm(bool compress) {
  return compress ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
}
}  // namespace

bool EccNativeKey::InitNew() {
  // Step 1: Initialize the EC_KEY.
  _key = EC_KEY_new_by_curve_name(kSecp256k1Id);
  if (!_key) {
    LOG_ERROR("Failed to create EC_KEY: key_nid = %d", kSecp256k1Id);
    return false;
  }
  // Step 2: Generate key.
  if (!EC_KEY_generate_key(_key.Get())) {
    LOG_ERROR("Failed to generate new key");
    return false;
  }
  // Step 3: Finalize.
  if (!CheckEcKey(_key.Get())) {
    LOG_ERROR("EC_KEY is invalid");
    return false;
  }
  SetEcKeyFlags(_key.Get());
  _is_private = true;
  return true;
}

bool EccNativeKey::InitFromSubjectPublicKeyInfo(
    const std::vector<uint8_t> &key_info) {
  if (key_info.empty()) {
    LOG_ERROR("SubjectPublicKeyInfo is empty");
    return false;
  }
  // Step 1: Parse |key_info| as SubjectPublicKeyInfo.
  const uint8_t *pp = key_info.data();
  EvpKeyPointer pkey =
      d2i_PUBKEY(nullptr, &pp, static_cast<long>(key_info.size()));
  if (!pkey) {
    LOG_ERROR("Failed to decode SubjectPublicKeyInfo");
    return false;
  }
  // Step 2: Verify that the returned key is ECC.
  const int base_nid = EVP_PKEY_base_id(pkey.Get());
  if (base_nid != EVP_PKEY_EC) {
    LOG_ERROR(
        "SubjectPublicKeyInfo is not an ECC key: base_nid = %d", base_nid);
    return false;
  }
  // Step 3: Convert from EVP_PKEY to EC_KEY.
  EcKeyPointer ec_key = EVP_PKEY_get1_EC_KEY(pkey.Get());
  if (!ec_key) {
    LOG_ERROR("Failed to extract EC_KEY from EVP_PKEY");
    return false;
  }
  // Step 4: Verify that the key curve is supported.
  const EC_GROUP *group = EC_KEY_get0_group(ec_key.Get());
  if (group == nullptr) {
    LOG_ERROR("Failed to get EC_GROUP from EC_KEY");
    return false;
  }
  const int key_nid = EC_GROUP_get_curve_name(group);
  if (key_nid != kSecp256k1Id) {
    LOG_ERROR(
        "SubjectPublicKeyInfo is not a supported ECC key type: nid = %d",
        key_nid);
    return false;
  }
  // Step 5: Take ownership of EC_KEY.
  _key = std::move(ec_key);
  if (!_key) {
    LOG_ERROR("Failed to obtain EC_KEY");
    return false;
  }
  // Step 6: Finalize.
  if (!CheckEcKey(_key.Get())) {
    LOG_ERROR("EC_KEY is invalid");
    return false;
  }
  SetEcKeyFlags(_key.Get());
  _is_private = false;
  return true;
}

bool EccNativeKey::InitFromPrivateKeyInfo(
    const std::vector<uint8_t> &key_info) {
  if (key_info.empty()) {
    LOG_ERROR("PrivateKeyInfo is empty");
    return false;
  }
  // Step 1: Parse |key_info| as PrivateKeyInfo.
  const uint8_t *pp = key_info.data();
  EvpKeyPointer pkey =
      d2i_AutoPrivateKey(nullptr, &pp, static_cast<long>(key_info.size()));
  if (!pkey) {
    LOG_ERROR("Failed to decode PrivateKeyInfo");
    return false;
  }
  // Step 2: Verify that the returned code is ECC.
  const int base_nid = EVP_PKEY_base_id(pkey.Get());
  if (base_nid != EVP_PKEY_EC) {
    LOG_ERROR("PrivateKeyInfo is not an ECC key: base_nid = %d", base_nid);
    return false;
  }
  // Step 3: Convert from EVP_PKEY to EC_KEY.
  EcKeyPointer ec_key = EVP_PKEY_get1_EC_KEY(pkey.Get());
  if (!ec_key) {
    LOG_ERROR("Failed to extract EC_KEY from EVP_PKEY");
    return false;
  }
  // Step 4: Verify that the key curve is supported.
  const EC_GROUP *group = EC_KEY_get0_group(ec_key.Get());
  if (group == nullptr) {
    LOG_ERROR("Failed to get EC_GROUP from EC_KEY");
    return false;
  }
  const int key_nid = EC_GROUP_get_curve_name(group);
  if (key_nid != kSecp256k1Id) {
    LOG_ERROR(
        "PrivateKeyInfo is not a supported ECC key type: nid = %d", key_nid);
    return false;
  }
  // Step 5: Take ownership of EC_KEY.
  _key = std::move(ec_key);
  if (!_key) {
    LOG_ERROR("Failed to obtain EC_KEY");
    return false;
  }
  // Step 4: Finalize.
  if (!CheckEcKey(_key.Get())) {
    LOG_ERROR("EC_KEY is invalid");
    return false;
  }
  SetEcKeyFlags(_key.Get());
  _is_private = true;
  return true;
}

bool EccNativeKey::InitFromPoint(const std::vector<uint8_t> &ecc_point) {
  if (ecc_point.empty()) {
    LOG_ERROR("Encoded ECC point is empty");
    return false;
  }
  // Step 1: Initialize the EC_KEY.
  _key = EC_KEY_new_by_curve_name(kSecp256k1Id);
  if (!_key) {
    LOG_ERROR("Failed to create EC_KEY: key_nid = %d", kSecp256k1Id);
    return false;
  }
  // Step 2: Decode the point into the EC_KEY.
  BnCtxPointer bn_ctx = BN_CTX_new();
  if (!bn_ctx) {
    LOG_ERROR("Failed to allocate a BN context");
    return false;
  }
  if (!EC_KEY_oct2key(
          _key.Get(), ecc_point.data(), ecc_point.size(), bn_ctx.Get())) {
    LOG_ERROR("Failed to load the ECC point into the key");
    return false;
  }
  // Step 3: Finalize.
  if (!CheckEcKey(_key.Get())) {
    LOG_ERROR("EC_KEY is invalid");
    return false;
  }
  SetEcKeyFlags(_key.Get());
  _is_private = false;
  return true;
}

bool EccNativeKey::InitFromScalar(const std::vector<uint8_t> &ecc_scalar) {
  if (ecc_scalar.empty()) {
    LOG_ERROR("Encoded ECC scalar is empty");
    return false;
  }
  // Step 1: Initialize the EC_KEY.
  _key = EC_KEY_new_by_curve_name(kSecp256k1Id);
  if (!_key) {
    LOG_ERROR("Failed to create EC_KEY: key_nid = %d", kSecp256k1Id);
    return false;
  }
  // Step 2: Decode the scalar into the EC_KEY.
  if (!EC_KEY_oct2priv(_key.Get(), ecc_scalar.data(), ecc_scalar.size())) {
    LOG_ERROR("Failed to load the ECC scalar into the key");
    return false;
  }
  // Step 3: Regenerate public key from private key.
  const EC_GROUP *group = EC_KEY_get0_group(_key.Get());
  if (group == nullptr) {
    LOG_ERROR("Failed to get group from EC key");
    return false;
  }
  const BIGNUM *priv_scalar = EC_KEY_get0_private_key(_key.Get());
  if (priv_scalar == nullptr) {
    LOG_ERROR("Failed to get private scalar from EC key");
    return false;
  }
  EcPointPointer pub_point = EC_POINT_new(group);
  if (!pub_point) {
    LOG_ERROR("Failed to allocate EC point");
    return false;
  }
  BnCtxPointer bn_ctx = BN_CTX_new();
  if (!bn_ctx) {
    LOG_ERROR("Failed to allocate a BN context");
    return false;
  }
  // r = n * G
  const int res = EC_POINT_mul(
      group,
      /* r = */ pub_point.Get(),
      /* n = */ priv_scalar, nullptr, nullptr, bn_ctx.Get());
  if (!res) {
    LOG_ERROR("Failed to calculate public key point");
    return false;
  }
  if (!EC_KEY_set_public_key(_key.Get(), pub_point.Get())) {
    LOG_ERROR("Failed to set public key point");
    return false;
  }
  // Step 4: Finalize.
  if (!CheckEcKey(_key.Get())) {
    LOG_ERROR("EC_KEY is invalid");
    return false;
  }
  SetEcKeyFlags(_key.Get());
  _is_private = true;
  return true;
}

std::vector<uint8_t> EccNativeKey::SerializeSubjectPublicKeyInfo() const {
  LOG_ERROR("Not implemented");
  EvpKeyPointer pkey = EVP_PKEY_new();
  if (!pkey) {
    LOG_ERROR("Failed to allocate EVP_PKEY");
    return {};
  }
  if (!EVP_PKEY_set1_EC_KEY(pkey.Get(), const_cast<EC_KEY *>(_key.Get()))) {
    LOG_ERROR("Failed to convert to EVP_PKEY");
    return {};
  }
  if (EVP_PKEY_EC != EVP_PKEY_base_id(pkey.Get())) {
    LOG_ERROR("EVP_PKEY not properly set");
    return {};
  }
  uint8_t *pp = nullptr;
  const int size = i2d_PUBKEY(pkey.Get(), &pp);
  if (size <= 0 || pp == nullptr) {
    LOG_ERROR("Failed to serialize to SubjectPublicKeyInfo");
    return {};
  }
  std::vector<uint8_t> key_info(pp, pp + size);
  OPENSSL_free(pp);
  return key_info;
}

std::vector<uint8_t> EccNativeKey::SerializePrivateKeyInfo() const {
  DASSERT(_is_private);
  EvpKeyPointer pkey = EVP_PKEY_new();
  if (!pkey) {
    LOG_ERROR("Failed to allocate EVP_PKEY");
    return {};
  }
  if (!EVP_PKEY_set1_EC_KEY(pkey.Get(), const_cast<EC_KEY *>(_key.Get()))) {
    LOG_ERROR("Failed to convert to EVP_PKEY");
    return {};
  }
  if (EVP_PKEY_EC != EVP_PKEY_base_id(pkey.Get())) {
    LOG_ERROR("EVP_PKEY not properly set");
    return {};
  }
  uint8_t *pp = nullptr;
  const int size = i2d_PrivateKey(pkey.Get(), &pp);
  if (size <= 0 || pp == nullptr) {
    LOG_ERROR("Failed to serialize to PrivateKeyInfo");
    return {};
  }
  std::vector<uint8_t> key_info(pp, pp + size);
  OPENSSL_free(pp);
  return key_info;
}

std::vector<uint8_t> EccNativeKey::SerializeAsPublicPoint(bool compress) const {
  BnCtxPointer bn_ctx = BN_CTX_new();
  if (!bn_ctx) {
    LOG_ERROR("Failed to allocate a BN context");
    return {};
  }
  uint8_t *data = nullptr;
  const size_t size = EC_KEY_key2buf(
      _key.Get(), OpenSslPointConversionForm(compress), &data, bn_ctx.Get());
  if (size == 0 || data == nullptr) {
    LOG_ERROR("Failed to encode public point");
    return {};
  }
  std::vector<uint8_t> key_info(data, data + size);
  OPENSSL_free(data);
  return key_info;
}

std::vector<uint8_t> EccNativeKey::SerializeAsPrivateScalar() const {
  DASSERT(_is_private);
  uint8_t *data = nullptr;
  const size_t size = EC_KEY_priv2buf(_key.Get(), &data);
  if (size == 0 || data == nullptr) {
    LOG_ERROR("Failed to encode public point");
    return {};
  }
  std::vector<uint8_t> key_info(data, data + size);
  OPENSSL_free(data);
  return key_info;
}

bool EccNativeKey::VerifySignature(
    const uint8_t *data, size_t data_size,
    const std::vector<uint8_t> &signature) const {
  DASSERT(data != nullptr);
  DASSERT(data_size > 0);
  if (signature.empty()) {
    LOG_ERROR("Signature is empty");
    return false;
  }
  if (signature.size() > kMaxInt) {
    LOG_ERROR("Signature is too large for implementation");
    return false;
  }
  // Step 1: Digest message.
  const std::vector<uint8_t> digest = Sha256Sha256(data, data_size);
  if (digest.empty()) {
    LOG_ERROR("Failed to digest message");
    return false;
  }
  DASSERT(digest.size() <= kMaxInt);
  // Step 2: Verify message.
  const int res = ECDSA_verify(
      0, digest.data(), static_cast<int>(digest.size()), signature.data(),
      static_cast<int>(signature.size()), const_cast<EC_KEY *>(_key.Get()));
  if (res == -1) {
    LOG_ERROR("Failed to verify signature");
    return false;
  }
  return res == 1;
}

std::vector<uint8_t> EccNativeKey::GenerateSignature(
    const uint8_t *data, size_t data_size) const {
  DASSERT(_is_private);
  DASSERT(data != nullptr);
  DASSERT(data_size > 0);
  // Step 1: Digest message.
  const std::vector<uint8_t> digest = Sha256Sha256(data, data_size);
  if (digest.empty()) {
    LOG_ERROR("Failed to digest message");
    return {};
  }
  DASSERT(digest.size() <= kMaxInt);
  // Step 2: Verify message.
  unsigned int signature_length = ECDSA_size(_key.Get());
  std::vector<uint8_t> signature(signature_length);
  const int res = ECDSA_sign(
      0, digest.data(), static_cast<int>(digest.size()), signature.data(),
      &signature_length, const_cast<EC_KEY *>(_key.Get()));
  if (res == 0) {
    LOG_ERROR("Failed to generate signature");
    return {};
  }
  signature.resize(signature_length);
  return signature;
}
}  // namespace internal
using internal::EccNativeKey;

// ==== ==== Public Key ==== ====

EccPublicKey::EccPublicKey(std::unique_ptr<EccNativeKey> &&key):
    _key(std::move(key)) {}

EccPublicKey::~EccPublicKey() {}

// static
std::unique_ptr<EccPublicKey> EccPublicKey::LoadSubjectPublicKeyInfo(
    const std::vector<uint8_t> &key_info) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadSubjectPublicKeyInfo(key_info);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPublicKey>(new EccPublicKey(std::move(native_key)));
}

// static
std::unique_ptr<EccPublicKey> EccPublicKey::LoadPrivateKeyInfo(
    const std::vector<uint8_t> &key_info) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadPrivateKeyInfo(key_info);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPublicKey>(new EccPublicKey(std::move(native_key)));
}

// static
std::unique_ptr<EccPublicKey> EccPublicKey::LoadAsPoint(
    const std::vector<uint8_t> &ecc_point) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadAsPoint(ecc_point);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPublicKey>(new EccPublicKey(std::move(native_key)));
}

// static
std::unique_ptr<EccPublicKey> EccPublicKey::LoadAsScalar(
    const std::vector<uint8_t> &ecc_scalar) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadAsScalar(ecc_scalar);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPublicKey>(new EccPublicKey(std::move(native_key)));
}

std::vector<uint8_t> EccPublicKey::SerializeSubjectPublicKeyInfo() const {
  return _key->SerializeSubjectPublicKeyInfo();
}

std::vector<uint8_t> EccPublicKey::SerializeAsPublicPoint(bool compress) const {
  return _key->SerializeAsPublicPoint(compress);
}

bool EccPublicKey::VerifySignature(
    const std::string &data, const std::vector<uint8_t> &signature) const {
  if (data.empty()) {
    LOG_ERROR("Provided data is empty");
    return false;
  }
  return _key->VerifySignature(
      reinterpret_cast<const uint8_t *>(data.data()), data.size(), signature);
}

bool EccPublicKey::VerifySignature(
    const std::vector<uint8_t> &data,
    const std::vector<uint8_t> &signature) const {
  if (data.empty()) {
    LOG_ERROR("Provided data is empty");
    return false;
  }
  return _key->VerifySignature(data.data(), data.size(), signature);
}

bool EccPublicKey::VerifySignature(
    const uint8_t *data, size_t data_size,
    const std::vector<uint8_t> &signature) const {
  if (data == nullptr || data_size == 0) {
    LOG_ERROR("Provided data is %s", data == nullptr ? "null" : "empty");
    return false;
  }
  return _key->VerifySignature(data, data_size, signature);
}

// ==== ==== Private Key ==== ====

EccPrivateKey::EccPrivateKey(std::unique_ptr<EccNativeKey> &&key):
    EccPublicKey(std::move(key)) {
  DASSERT(_key->is_private());
}
EccPrivateKey::~EccPrivateKey() {}

// static
std::unique_ptr<EccPrivateKey> EccPrivateKey::New() {
  std::unique_ptr<EccNativeKey> native_key = EccNativeKey::New();
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPrivateKey>(
      new EccPrivateKey(std::move(native_key)));
}

// static
std::unique_ptr<EccPrivateKey> EccPrivateKey::LoadPrivateKeyInfo(
    const std::vector<uint8_t> &key_info) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadPrivateKeyInfo(key_info);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPrivateKey>(
      new EccPrivateKey(std::move(native_key)));
}
// static
std::unique_ptr<EccPrivateKey> EccPrivateKey::LoadAsScalar(
    const std::vector<uint8_t> &ecc_scalar) {
  std::unique_ptr<EccNativeKey> native_key =
      EccNativeKey::LoadAsScalar(ecc_scalar);
  if (!native_key) return nullptr;
  return std::unique_ptr<EccPrivateKey>(
      new EccPrivateKey(std::move(native_key)));
}

std::vector<uint8_t> EccPrivateKey::SerializePrivateKeyInfo() const {
  return _key->SerializePrivateKeyInfo();
}

std::vector<uint8_t> EccPrivateKey::SerializeAsPrivateScalar() const {
  return _key->SerializeAsPrivateScalar();
}

std::vector<uint8_t> EccPrivateKey::GenerateSignature(
    const std::string &data) const {
  if (data.empty()) {
    LOG_ERROR("Provided data is empty");
    return {};
  }
  return _key->GenerateSignature(
      reinterpret_cast<const uint8_t *>(data.data()), data.size());
}
std::vector<uint8_t> EccPrivateKey::GenerateSignature(
    const std::vector<uint8_t> &data) const {
  if (data.empty()) {
    LOG_ERROR("Provided data is empty");
    return {};
  }
  return _key->GenerateSignature(data.data(), data.size());
}

std::vector<uint8_t> EccPrivateKey::GenerateSignature(
    const uint8_t *data, size_t data_size) const {
  if (data == nullptr || data_size == 0) {
    LOG_ERROR("Provided data is %s", data == nullptr ? "null" : "empty");
    return {};
  }
  return _key->GenerateSignature(data, data_size);
}
}  // namespace crypto
}  // namespace btc
