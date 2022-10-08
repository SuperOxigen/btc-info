// Bitcoin Info - Compiler Helpers - Debug
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_DEBUG_H_
#define _BTC_CC_DEBUG_H_

#include "btc/cc/platform.h"

#ifdef BTC_DEBUG
#  include <assert.h>
// A debug only assert statement.  Intended for checking pre or post
// conditions of a function or method.
#  define DASSERT(expression) assert((expression))
// Programmatic breakpoints.  These should be found in commited code.
#  if defined(BTC_OS_LINUX) || defined(BTC_OS_APPLE)
#    include <signal.h>
#    define __BREAKPOINT raise(SIGTRAP)
#  elif defined(BTC_OS_WINDOWS)
#    define __BREAKPOINT __debugbreak
#  endif  // __BREAKPOINT
#else
#  define DASSERT(expression)
#  define __BREAKPOINT
#endif  // BTC_DEBUG

#endif  // _BTC_CC_DEBUG_H_
