// Bitcoin Info - Encoders - Hexadecimal Encoder
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_ENCODE_HEX_HPP_
#define _BTC_ENCODE_HEX_HPP_
#include <string>
#include <vector>

#include "btc/cc/attr.h"
#include "btc/cc/base.h"

namespace btc {
namespace encode {
// Checks if the provided string a correctly formatted hexadecimal string.
bool IsHexString(const std::string &hex);

// Bytes to Hexadecimal.
std::string HexEncode(const uint8_t *data, size_t size, bool reverse = false)
    __NOT_NULL(1);
std::string HexEncode(const std::vector<uint8_t> &data, bool reverse = false);
// Input string is treated as raw bytes.
std::string HexEncode(const std::string &data, bool reverse = false);

// Hexadecimal to bytes.
// Returns the number of bytes deserialized, or the number of bytes
// required to decode the whole string.
size_t HexDecode(
    const std::string &hex, uint8_t *buffer, size_t buffer_size,
    bool reverse = false) __NOT_NULL(2);
std::vector<uint8_t> HexDecode(const std::string &hex, bool reverse = false);
std::string HexDecodeToString(const std::string &hex, bool reverse = false);
}  // namespace encode
}  // namespace btc

#endif  // _BTC_ENCODE_HEX_HPP_
