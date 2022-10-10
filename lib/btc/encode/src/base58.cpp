// Bitcoin Info - Encoders - Base58 Encoder
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <algorithm>

#include "btc/encode/base58.hpp"

namespace btc {
namespace encode {
namespace {
const char kBase58CharSet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
}  // namespace

bool IsBase58Character(char c) {
  if (c >= '1' && c <= '9') return true;
  if (c >= 'A' && c <= 'Z') {
    return c != 'I' && c != 'O';
  }
  if (c >= 'a' && c <= 'z') {
    return c != 'l';
  }
  return false;
}

uint8_t Base58CharToValue(char c) {
  if (c >= '1' && c <= '9') {
    return (c - '1');
  }
  if (c >= 'A' && c <= 'H') {
    return (c - 'A') + 9;
  }
  if (c >= 'J' && c <= 'N') {
    return (c - 'J') + 17;
  }
  if (c >= 'P' && c <= 'Z') {
    return (c - 'P') + 22;
  }
  if (c >= 'a' && c <= 'k') {
    return (c - 'a') + 33;
  }
  if (c >= 'm' && c <= 'z') {
    return (c - 'm') + 44;
  }
  return 0xff;
}

char ValueToBase58Char(uint8_t v) {
  if (v >= 58) {
    return 0;
  }
  return kBase58CharSet[v];
}

bool IsBase58String(const std::string &b58) {
  if (b58.empty()) return true;
  return std::all_of(b58.begin(), b58.end(), IsBase58Character);
}
}  // namespace encode
}  // namespace btc
