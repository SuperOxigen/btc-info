// Bitcoin Info - Cryptography - ECC Key - Unittest
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <gtest/gtest.h>

#include "btc/crypto/ecc_key.hpp"

namespace btc {
namespace crypto {
namespace test {
namespace {
const std::string kMessageString = "Hello world!";
const std::vector<uint8_t> kMessageVector =
    std::vector<uint8_t>(kMessageString.begin(), kMessageString.end());
}  // namespace

class EccKeyTest: public ::testing::Test {
public:
  void SetUp() override {
    _private_key = EccPrivateKey::New();
    ASSERT_TRUE(_private_key) << "Failed to create key";
  }
  void TearDown() override { _private_key.reset(); }
  std::unique_ptr<EccPrivateKey> _private_key = nullptr;
};  // class EccKeyTest

TEST_F(EccKeyTest, GenerateSignature_FromString) {
  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_FALSE(signature.empty());
}

TEST_F(EccKeyTest, GenerateSignature_FromVector) {
  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageVector);
  EXPECT_FALSE(signature.empty());
}

TEST_F(EccKeyTest, GenerateSignature_FromRawBytes) {
  const std::vector<uint8_t> signature = _private_key->GenerateSignature(
      kMessageVector.data(), kMessageVector.size());
  EXPECT_FALSE(signature.empty());
}

TEST_F(EccKeyTest, VerifySignature_FromString) {
  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(_private_key->VerifySignature(kMessageString, signature));
}

TEST_F(EccKeyTest, VerifySignature_FromVector) {
  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(_private_key->VerifySignature(kMessageVector, signature));
}

TEST_F(EccKeyTest, VerifySignature_FromRawBytes) {
  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(_private_key->VerifySignature(
      kMessageVector.data(), kMessageVector.size(), signature));
}

TEST_F(EccKeyTest, VerifySignature_DifferentKeys) {
  auto other_private_key = EccPrivateKey::New();
  ASSERT_TRUE(other_private_key);

  std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  ASSERT_FALSE(signature.empty());
  EXPECT_FALSE(other_private_key->VerifySignature(kMessageString, signature));

  signature = other_private_key->GenerateSignature(kMessageString);
  ASSERT_FALSE(signature.empty());
  EXPECT_FALSE(_private_key->VerifySignature(kMessageString, signature));
}

TEST_F(EccKeyTest, LoadPublicKey_SubjectPublicKeyInfo) {
  const std::vector<uint8_t> key_info =
      _private_key->SerializeSubjectPublicKeyInfo();

  auto public_key = EccPublicKey::LoadSubjectPublicKeyInfo(key_info);
  ASSERT_TRUE(public_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(public_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_key_info =
      public_key->SerializeSubjectPublicKeyInfo();
  EXPECT_EQ(key_info, other_key_info);
}

TEST_F(EccKeyTest, LoadPublicKey_PrivateKeyInfo) {
  const std::vector<uint8_t> key_info = _private_key->SerializePrivateKeyInfo();

  auto public_key = EccPublicKey::LoadPrivateKeyInfo(key_info);
  ASSERT_TRUE(public_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(public_key->VerifySignature(kMessageString, signature));
}

TEST_F(EccKeyTest, LoadPublicKey_PublicPoint_Compressed) {
  constexpr bool kCompressed = true;
  const std::vector<uint8_t> key_info =
      _private_key->SerializeAsPublicPoint(kCompressed);

  auto public_key = EccPublicKey::LoadAsPoint(key_info);
  ASSERT_TRUE(public_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(public_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_key_info =
      public_key->SerializeAsPublicPoint(kCompressed);
  EXPECT_EQ(key_info, other_key_info);
}

TEST_F(EccKeyTest, LoadPublicKey_PublicPoint_Uncompressed) {
  constexpr bool kUncompressed = false;
  const std::vector<uint8_t> key_info =
      _private_key->SerializeAsPublicPoint(kUncompressed);

  auto public_key = EccPublicKey::LoadAsPoint(key_info);
  ASSERT_TRUE(public_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(public_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_key_info =
      public_key->SerializeAsPublicPoint(kUncompressed);
  EXPECT_EQ(key_info, other_key_info);
}

TEST_F(EccKeyTest, LoadPublicKey_PrivateScalar) {
  const std::vector<uint8_t> key_info =
      _private_key->SerializeAsPrivateScalar();

  auto public_key = EccPublicKey::LoadAsScalar(key_info);
  ASSERT_TRUE(public_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(public_key->VerifySignature(kMessageString, signature));
}

TEST_F(EccKeyTest, LoadPrivateKey_PrivateKeyInfo) {
  const std::vector<uint8_t> key_info = _private_key->SerializePrivateKeyInfo();

  auto other_private_key = EccPrivateKey::LoadPrivateKeyInfo(key_info);
  ASSERT_TRUE(other_private_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(other_private_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_signature =
      other_private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(_private_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_key_info =
      other_private_key->SerializePrivateKeyInfo();
  EXPECT_EQ(key_info, other_key_info);
}

TEST_F(EccKeyTest, LoadPrivateKey_PrivateScalar) {
  const std::vector<uint8_t> key_info =
      _private_key->SerializeAsPrivateScalar();

  auto other_private_key = EccPrivateKey::LoadAsScalar(key_info);
  ASSERT_TRUE(other_private_key);

  const std::vector<uint8_t> signature =
      _private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(other_private_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_signature =
      other_private_key->GenerateSignature(kMessageString);
  EXPECT_TRUE(_private_key->VerifySignature(kMessageString, signature));

  const std::vector<uint8_t> other_key_info =
      other_private_key->SerializeAsPrivateScalar();
  EXPECT_EQ(key_info, other_key_info);
}
}  // namespace test
}  // namespace crypto
}  // namespace btc
