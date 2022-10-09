// Bitcoin Info - Cryptography - Digester
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CRYPTO_DIGESTER_HPP_
#define _BTC_CRYPTO_DIGESTER_HPP_

#include <memory>
#include <string>
#include <vector>

#include "btc/cc/base.h"
#include "btc/cc/classy.hpp"
#include "btc/crypto/digest.hpp"

namespace btc {
namespace crypto {

namespace internal {
class NativeDigester;
}  // namespace internal

class Digester {
public:
  BTC_DISALLOW_COPY_AND_MOVE(Digester);
  ~Digester();

  static std::unique_ptr<Digester> New(DigestAlgorithm algorithm);

  DigestAlgorithm algorithm() const { return _algorithm; }

  // Length of the output digest.
  size_t digest_length() const { return _digest_length; }

  // Number of bytes that have been digested.
  size_t Count() const { return _byte_count; }

  // Reset the digester to empty.
  void Reset();

  bool Update(uint8_t datum);
  bool Update(const std::string &data);
  bool Update(const std::vector<uint8_t> &data);
  bool Update(const uint8_t *data, size_t data_size);

  bool Finalize(uint8_t *digest);
  std::vector<uint8_t> Finalize();

private:
  Digester(
      DigestAlgorithm algorithm,
      std::unique_ptr<internal::NativeDigester> &&native_digester);

  const DigestAlgorithm _algorithm;
  const size_t _digest_length;
  size_t _byte_count = 0;
  std::unique_ptr<internal::NativeDigester> _digester;
};  // class Digester
}  // namespace crypto
}  // namespace btc

#endif  // _BTC_CRYPTO_DIGESTER_HPP_
