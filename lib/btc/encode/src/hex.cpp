// Bitcoin Info - Encoders - Hexadecimal Encoder
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <ctype.h>

#include <algorithm>

#include "btc/cc/debug.h"
#include "btc/encode/hex.hpp"
#include "btc/log.h"

namespace btc {
namespace encode {
namespace {
const char kLowerHexSet[] = "0123456789abcdef";

// Internal hexadecimal encoder.
// Assumes that the buffer pointed to by |hex| is two times |size|.  The
// null terminator should be applied by the caller if required.
bool HexEncodeInternal(
    const uint8_t *data, size_t size, char *hex, bool reverse) {
  DASSERT(data != nullptr);
  DASSERT(size > 0);
  DASSERT(hex != nullptr);
  if (reverse) {
    for (size_t i = 0; i < size; i++) {
      hex[i * 2] = kLowerHexSet[(data[size - i - 1] >> 4) & 0xF];
      hex[i * 2 + 1] = kLowerHexSet[data[size - i - 1] & 0xF];
    }
  } else {
    for (size_t i = 0; i < size; i++) {
      hex[i * 2] = kLowerHexSet[(data[i] >> 4) & 0xF];
      hex[i * 2 + 1] = kLowerHexSet[data[i] & 0xF];
    }
  }
  return true;
}

bool HexDecodeCharacter(char c, uint8_t *nibble, bool high) {
  DASSERT(nibble != nullptr);
  uint8_t value = 0;
  if (isdigit(c)) {
    value = c - '0';
  } else if (c >= 'A' && c <= 'F') {
    value = (c - 'A') + 10;
  } else if (c >= 'a' && c <= 'f') {
    value = (c - 'a') + 10;
  } else {
    return false;  // Not a hex character.
  }
  if (high) {
    *nibble = (*nibble & 0xF) | ((value << 4) & 0xF0);
  } else {
    *nibble = (*nibble & 0xF0) | (value & 0xF);
  }
  return true;
}

// Internal hexadecimal decoder.
// Assumes that the buffer pointed to by |data| is at least half the
// size of |hex_size|.
bool HexDecodeInternal(
    const char *hex, size_t hex_size, uint8_t *data, bool reverse) {
  DASSERT(hex != nullptr);
  DASSERT((hex_size & 1) == 0);
  DASSERT(data != nullptr);
  const size_t data_size = hex_size / 2;
  for (size_t i = 0; i < hex_size; i += 2) {
    const size_t didx = reverse ? (data_size - (i / 2) - 1) : (i / 2);
    if (!HexDecodeCharacter(hex[i], &data[didx], true)) {
      LOG_DEBUG("Not a hex digit: c = 0x%02x, index = %zu", hex[i], i);
      return false;
    }
    if (!HexDecodeCharacter(hex[i + 1], &data[didx], false)) {
      LOG_DEBUG("Not a hex digit: c = 0x%02x, index = %zu", hex[i + 1], i + 1);
      return false;
    }
  }
  return true;
}
}  // namespace

bool IsHexString(const std::string &hex) {
  if (hex.empty()) return true;
  if (hex.size() & 1) return false;
  return std::all_of(hex.cbegin(), hex.cend(), ::isxdigit);
}

std::string HexEncode(const uint8_t *data, size_t size, bool reverse) {
  DASSERT(data != nullptr);
  if (size == 0) return "";
  std::string hex(size * 2, 'x');
  const bool res = HexEncodeInternal(data, size, &hex.front(), reverse);
  if (!res) {
    hex.clear();
  }
  return hex;
}

std::string HexEncode(const std::vector<uint8_t> &data, bool reverse) {
  if (data.empty()) return "";
  std::string hex(data.size() * 2, 'X');
  const bool res =
      HexEncodeInternal(data.data(), data.size(), &hex.front(), reverse);
  if (!res) {
    hex.clear();
  }
  return hex;
}

std::string HexEncode(const std::string &data, bool reverse) {
  if (data.empty()) return "";
  std::string hex(data.size() * 2, 'X');
  const bool res = HexEncodeInternal(
      reinterpret_cast<const uint8_t *>(data.data()), data.size(), &hex.front(),
      reverse);
  if (!res) {
    hex.clear();
  }
  return hex;
}

size_t HexDecode(
    const std::string &hex, uint8_t *buffer, size_t buffer_size, bool reverse) {
  DASSERT(buffer != nullptr);
  if (hex.size() & 1) {
    LOG_DEBUG("Provided string is odd length: %zu", hex.size());
    return 0;
  }
  if (hex.empty()) return 0;
  if (buffer_size == 0) return hex.size() / 2;
  const size_t decode_size = std::min(hex.size(), buffer_size * 2);
  const bool res = HexDecodeInternal(hex.data(), decode_size, buffer, reverse);
  return res ? hex.size() / 2 : 0;
}

std::vector<uint8_t> HexDecode(const std::string &hex, bool reverse) {
  std::vector<uint8_t> data;
  if (hex.empty()) return data;
  if (hex.size() & 1) {
    LOG_DEBUG("Provided string is odd length: %zu", hex.size());
    return data;
  }
  data.resize(hex.size() / 2);
  const bool res =
      HexDecodeInternal(hex.data(), hex.size(), data.data(), reverse);
  if (!res) data.clear();
  return data;
}

std::string HexDecodeToString(const std::string &hex, bool reverse) {
  std::string data;
  if (hex.empty()) return data;
  if (hex.size() & 1) {
    LOG_DEBUG("Provided string is odd length: %zu", hex.size());
    return data;
  }
  data.assign(hex.size() / 2, ' ');
  const bool res = HexDecodeInternal(
      hex.data(), hex.size(), reinterpret_cast<uint8_t *>(&data.front()),
      reverse);
  if (!res) data.clear();
  return data;
}
}  // namespace encode
}  // namespace btc
