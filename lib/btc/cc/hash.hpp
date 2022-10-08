// Bitcoin Info - Compiler Helpers - STD Hash
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_HASH_HPP_
#define _BTC_CC_HASH_HPP_

#include <functional>

// Defines a template specialization of std::hash<> for
// classes which implement a Hash() function.
#define __DEFINE_STD_HASH(ClassName)                                          \
  template<>                                                                  \
  struct std::hash<ClassName> {                                               \
    std::size_t operator()(const ClassName &obj) const { return obj.Hash(); } \
  }

#endif  // _BTC_CC_HASH_HPP_
