// Bitcoin Info - Compiler Helpers - Base
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_BASE_H_
#define _BTC_CC_BASE_H_

#include "btc/cc/platform.h"

#ifdef BTC_OS_LINUX
// Enable basic features if not explicitly set.
#  ifndef _GNU_SOURCE
#    ifndef _XOPEN_SOURCE
#      define _XOPEN_SOURCE 700
#    endif
#    ifndef _DEFAULT_SOURCE
#      define _DEFAULT_SOURCE 1
#    endif
#  endif  // _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Protect C-style function linking.
#ifdef BTC_LANG_CPP
#  define __C_SECTION_BEGIN extern "C" {
#  define __C_SECTION_END }
#  define __C_FUNCTION extern "C"
#else
#  define __C_SECTION_BEGIN
#  define __C_SECTION_END
#  define __C_FUNCTION
#endif

typedef intmax_t offset_t;

#endif  // _BTC_CC_BASE_H_
