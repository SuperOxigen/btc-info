// Bitcoin Info - Encoders - Base58 Encoder
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_ENCODE_BASE58_HPP_
#define _BTC_ENCODE_BASE58_HPP_
#include <string>
#include <vector>

#include "btc/cc/attr.h"
#include "btc/cc/base.h"

namespace btc {
namespace encode {
bool IsBase58Character(char c);
uint8_t Base58CharToValue(char c);
char ValueToBase58Char(uint8_t v);

// Checks if the provided string a correctly formatted base58 string.
bool IsBase58String(const std::string &b58);

// Bytes to Base58.
std::string Base58Encode(const uint8_t *data, size_t size) __NOT_NULL(1);
std::string Base58Encode(const std::vector<uint8_t> &data);
// Input string is treated as raw bytes.
std::string Base58Encode(const std::string &data);

// Base58 to bytes.
//
// Returns the number of bytes deserialized, or the number of bytes
// required to decode the whole string.
// If |buffer_size| is too small, the output will be truncated to
// |buffer_size| and the result will be the actual size of the
// decoded value.
size_t Base58Decode(const std::string &b58, uint8_t *buffer, size_t buffer_size)
    __NOT_NULL(2);
std::vector<uint8_t> Base58Decode(const std::string &b58);
std::string Base58DecodeToString(const std::string &b58);
}  // namespace encode
}  // namespace btc

#endif  // _BTC_ENCODE_BASE58_HPP_
