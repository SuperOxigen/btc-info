// Bitcoin Info - Logging
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_LOG_H_
#define _BTC_LOG_H_

#include "btc/cc/attr.h"
#include "btc/cc/base.h"

__C_SECTION_BEGIN;
typedef enum {
  BTC_LOG_VERBOSE,
  BTC_LOG_DEBUG,
  BTC_LOG_INFO,
  BTC_LOG_WARN,
  BTC_LOG_ERROR,
  BTC_LOG_FATAL
} btc_log_level_t;

size_t btc_log(
    btc_log_level_t level, const char *filename, uint32_t lineno,
    const char *tag, const char *format, ...) __PRINTF(5, 6);
__C_SECTION_END;

// Importing modules can define a tag which will be added to
// the log printout.
#ifndef BTC_LOG_TAG
#  define BTC_LOG_TAG NULL
#endif

#ifdef BTC_DEBUG
#  define LOG_DEBUG(fmt_args...) \
    btc_log(BTC_LOG_DEBUG, __FILE__, __LINE__, BTC_LOG_TAG, fmt_args)
#else
#  define LOG_DEBUG(fmt_args...)
#endif
#define LOG_INFO(fmt_args...) \
  btc_log(BTC_LOG_INFO, __FILE__, __LINE__, BTC_LOG_TAG, fmt_args)
#define LOG_WARN(fmt_args...) \
  btc_log(BTC_LOG_WARN, __FILE__, __LINE__, BTC_LOG_TAG, fmt_args)
#define LOG_ERROR(fmt_args...) \
  btc_log(BTC_LOG_ERROR, __FILE__, __LINE__, BTC_LOG_TAG, fmt_args)
#define LOG_FATAL(fmt_args...) \
  btc_log(BTC_LOG_FATAL, __FILE__, __LINE__, BTC_LOG_TAG, fmt_args)

#endif  // _BTC_LOG_H_
