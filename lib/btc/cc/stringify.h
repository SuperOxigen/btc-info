// Bitcoin Info - Compiler Helpers - Stringify
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_STRINGIFY_H_
#define _BTC_CC_STRINGIFY_H_

// Converts provided macros variables to a C string.
#define __STRINGIFY(x) #x
#define __STRINGIFY_MACRO(x) __STRINGIFY_MACRO_INTERNAL(x)
#define __STRINGIFY_MACRO_INTERNAL(x) #x

#endif  // _BTC_CC_STRINGIFY_H_
