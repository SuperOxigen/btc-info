// Bitcoin Info - Compiler Helpers - Attributes
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_ATTR_H_
#define _BTC_CC_ATTR_H_

#include "btc/cc/platform.h"

// Function and variable attributes.
#if defined(BTC_CC_GCC) || defined(BTC_CC_CLANG)
#  define __ALL_NOT_NULL __attribute__((nonnull))
#  define __COLD __attribute__((cold))
#  define __CONST __attribute__((const))
#  ifndef __DEPRECATED
#    define __DEPRECATED __attribute__((deprecated))
#  endif
#  define __HOT __attribute__((hot))
#  define __INTERRUPT __attribute__((interrupt))
#  define __NO_RETURN __attribute__((noreturn))
#  define __NOT_NULL(...) __attribute__((nonnull(__VA_ARGS__)))
#  define __PRINTF(fmt_idx, arg_idx) \
    __attribute__((format(printf, fmt_idx, arg_idx)))
#  define __RETURN_NOT_NULL __attribute__((returns_nonnull))
#  define __SETUP __attribute__((constructor))
#  define __TEARDOWN __attribute__((destructor))
#  define __UNUSED __attribute__((unused))
#else
#  define __ALL_NOT_NULL
#  define __COLD
#  define __CONST
#  define __DEPRECATED
#  define __HOT
#  define __INTERRUPT
#  define __NO_RETURN
#  define __NOT_NULL(...)
#  define __PRINTF(fmt_idx, arg_idx)
#  define __RETURN_NOT_NULL
#  define __SETUP
#  define __TEARDOWN
#  define __UNUSED
#endif

#endif  // _BTC_CC_ATTR_H_
