// Bitcoin Info - Logging
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <stdarg.h>
#include <stdio.h>

#include "btc/log.h"

static const char kUnknown[] = "U";
static const char kVerbose[] = "V";
static const char kDebug[] = "D";
static const char kInfo[] = "I";
static const char kWarn[] = "W";
static const char kError[] = "E";
static const char kFatal[] = "F";

static const char *level_to_string(btc_log_level_t level) {
  switch (level) {
    case BTC_LOG_VERBOSE:
      return kVerbose;
    case BTC_LOG_DEBUG:
      return kDebug;
    case BTC_LOG_INFO:
      return kInfo;
    case BTC_LOG_WARN:
      return kWarn;
    case BTC_LOG_ERROR:
      return kError;
    case BTC_LOG_FATAL:
      return kFatal;
    default:
      return kUnknown;
  }
}

size_t btc_log(
    btc_log_level_t level, const char *filename, uint32_t lineno,
    const char *tag, const char *format, ...) {
  if (format == NULL) return 0;

  int level_length;
  if (tag != NULL) {
    level_length =
        printf("[%s:%s:%s:%u] ", level_to_string(level), tag, filename, lineno);
  } else if (filename == NULL) {
    // If |filename| is not present, assume line number is also
    // invalid.
    level_length = printf("[%s:<unknown>:0] ", level_to_string(level));
  } else {
    level_length =
        printf("[%s:%s:%u] ", level_to_string(level), filename, lineno);
  }
  if (level_length <= 0) return 0;

  va_list ap;
  va_start(ap, format);
  const int content_lenth = vprintf(format, ap);
  va_end(ap);
  if (content_lenth < 0) return 0;

  const int end_char = printf("\n");
  if (content_lenth < 0) return 0;

  return ((size_t) level_length) + ((size_t) content_lenth)
       + ((size_t) end_char);
}
