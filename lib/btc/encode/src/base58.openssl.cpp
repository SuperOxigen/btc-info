// Bitcoin Info - Encoders - OpenSSL Base58 Encoder
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <algorithm>
#include <iterator>

#include <openssl/bn.h>

#include "btc/cc/debug.h"
#include "btc/encode/base58.hpp"
#include "btc/log.h"
#include "btc/mem/auto_ptr.hpp"

namespace btc {
namespace encode {
using BigNum = ::btc::mem::AutoPointer<BIGNUM, BN_free>;
using BigNumCtx = ::btc::mem::AutoPointer<BN_CTX, BN_CTX_free>;

namespace {
const char kBase58CharSet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

constexpr char ToBase58Char(uint8_t v) {
  return v < 58 ? kBase58CharSet[v] : '-';
}
}  // namespace

// == Encoding ==

std::string Base58Encode(const uint8_t *data, size_t size) {
  DASSERT(data != nullptr);
  if (size == 0) return "";
  // Determine leading zeros.
  size_t leading_zeros = 0;
  while (data[leading_zeros] == 0 && leading_zeros < size) leading_zeros++;
  // Special case, all zeros.
  if (leading_zeros == size) {
    return std::string(size, '1');
  }

  // Convert data to big-endian value.
  BigNum acc = BN_new();
  if (!acc) {
    LOG_ERROR("Failed to allocate accumulator");
    return "";
  }
  if (BN_bin2bn(data, static_cast<int>(size), acc.Get()) == nullptr) {
    LOG_ERROR("Failed to convert data to interger");
    return "";
  }
  // Initialize variables.
  BigNumCtx ctx = BN_CTX_new();
  if (!ctx) {
    LOG_ERROR("Failed to allocate counter CTX");
    return "";
  }
  BigNum rem = BN_new();
  if (!rem) {
    LOG_ERROR("Failed to allocate remainer");
    return "";
  }
  BigNum divisor = BN_new();
  if (!divisor) {
    LOG_ERROR("Failed to allocate divisor");
    return "";
  }
  if (!BN_set_word(divisor.Get(), 58)) {
    LOG_ERROR("Failed to set divisor");
    return "";
  }

  // Perform conversion to base 58.  |values| is in reverse order
  // from the final encoding.
  std::vector<uint8_t> values;
  while (!BN_is_zero(acc.Get())) {
    // int BN_div(dv, rem, a, d, ctx);  dv = a/b
    if (!BN_div(acc.Get(), rem.Get(), acc.Get(), divisor.Get(), ctx.Get())) {
      LOG_ERROR("Failed to perform division: step = %zu", values.size() + 1);
      return "";
    }
    const uint32_t value = BN_get_word(rem.Get());
    DASSERT(value < 58);
    values.push_back(static_cast<uint8_t>(value));
  }

  // Convert base58 values to base58 characters, reverse the order.
  std::string result(leading_zeros, '1');
  std::transform(
      values.rbegin(), values.rend(), std::back_inserter(result), ToBase58Char);
  return result;
}

std::string Base58Encode(const std::vector<uint8_t> &data) {
  if (data.empty()) return "";
  return Base58Encode(data.data(), data.size());
}

std::string Base58Encode(const std::string &data) {
  if (data.empty()) return "";
  return Base58Encode(
      reinterpret_cast<const uint8_t *>(data.data()), data.size());
}

// == Decoding ==

size_t Base58Decode(
    const std::string &b58, uint8_t *buffer, size_t buffer_size) {
  DASSERT(buffer != nullptr);
  const std::vector<uint8_t> res = Base58Decode(b58);
  if (buffer_size == 0) {
    return res.size();
  }
  if (res.empty()) {
    return 0;
  }
  const size_t copy_size = std::min(buffer_size, res.size());
  std::copy_n(res.begin(), copy_size, buffer);
  return res.size();
}

std::vector<uint8_t> Base58Decode(const std::string &b58) {
  if (!IsBase58String(b58)) {
    LOG_ERROR("String is not base58 encoded");
    return {};
  }
  if (b58.empty()) {
    return {};
  }
  // Count leading zeros (letter '1').
  size_t leading_zeros = 0;
  while (b58[leading_zeros] == '1' && leading_zeros < b58.size())
    leading_zeros++;
  // Special case, all zeros.
  if (leading_zeros == b58.size()) {
    return std::vector<uint8_t>(leading_zeros, 0);
  }
  // Convert string to values.
  std::vector<uint8_t> values;
  std::transform(
      b58.begin(), b58.end(), std::back_inserter(values), Base58CharToValue);
  // Initialize counters.
  BigNumCtx ctx = BN_CTX_new();
  if (!ctx) {
    LOG_ERROR("Failed to allocate counter CTX");
    return {};
  }
  BigNum acc = BN_new();
  if (!acc) {
    LOG_ERROR("Failed to allocate accumulator");
    return {};
  }
  BN_zero(acc.Get());
  BigNum value = BN_new();
  if (!value) {
    LOG_ERROR("Failed to allocate value");
    return {};
  }
  BigNum base = BN_new();
  if (!base) {
    LOG_ERROR("Failed to allocate multiplier");
    return {};
  }
  if (!BN_set_word(base.Get(), 58)) {
    LOG_ERROR("Failed to set multiplier");
    return {};
  }

  // Convert from base58 to integer.
  for (const uint8_t v : values) {
    // int BN_mul(r, a, b, ctx);  r = a * b
    if (!BN_mul(acc.Get(), acc.Get(), base.Get(), ctx.Get())) {
      LOG_ERROR("Failed to shift accumulator by 58");
      return {};
    }
    if (!BN_set_word(value.Get(), static_cast<uint32_t>(v))) {
      LOG_ERROR("Failed to set value");
      return {};
    }
    // int BN_add(r, a, b);  r = a + b
    if (!BN_add(acc.Get(), acc.Get(), value.Get())) {
      LOG_ERROR("Failed to add new value");
      return {};
    }
  }
  DASSERT(!BN_is_zero(acc.Get()));  // Should have been caught above.

  // Determine the final length.  Might add zero padding if necessary.
  const size_t actual_length = BN_num_bytes(acc.Get());
  const size_t pad_length = leading_zeros;
  const size_t total_length = actual_length + pad_length;
  std::vector<uint8_t> result(total_length);
  // Convert to binary.
  const int res =
      BN_bn2binpad(acc.Get(), result.data(), static_cast<int>(total_length));
  if (!res) {
    LOG_ERROR("Failed to convert accumulator to binary");
    return {};
  }
  return result;
}

std::string Base58DecodeToString(const std::string &b58) {
  const std::vector<uint8_t> res = Base58Decode(b58);
  if (res.empty()) return "";
  return std::string(res.begin(), res.end());
}
}  // namespace encode
}  // namespace btc
