// Bitcoin Info - Compiler Helpers - Platform
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_PLATFORM_H_
#define _BTC_CC_PLATFORM_H_

#include "btc/cc/stringify.h"

// Compiler
#if defined(__clang__)
#  define BTC_CC_CLANG
#  define BTC_CC "clang"
#  define BTC_CC_INFO                                                  \
    "clang-" __STRINGIFY_MACRO(__clang_major__) "." __STRINGIFY_MACRO( \
        __clang_minor__) "." __STRINGIFY_MACRO(__clang_patchlevel__)
#elif defined(__GNUC__)
#  define BTC_CC_GCC
#  define BTC_CC "gcc"
#  define BTC_CC_INFO                                         \
    "gcc-" __STRINGIFY_MACRO(__GNUC__) "." __STRINGIFY_MACRO( \
        __GNUC_MINOR__) "." __STRINGIFY_MACRO(__GNUC_PATCHLEVEL__)
#elif defined(_MSC_VER)
#  define BTC_CC_MSVS
#  define BTC_CC "MSVS"
#  define BTC_CC_INFO "MSVS-" __STRINGIFY_MACRO(_MSC_VER)
#else
#  error Cannot determine compiler
#endif

// Operating System - Unix/Linux/macOS/Windows
#if defined(__unix__) || defined(unix) || defined(__unix)
// Linux and macOS are considered Unix systems.
#  define BTC_OS_UNIX
#endif  // Unix
#if defined(__linux__) || defined(linux) || defined(__linux)
#  define BTC_OS_LINUX
#  define BTC_OS "Linux"
#elif defined(__APPLE__) || defined(__MACH__)
#  define BTC_OS_APPLE
#  define BTC_OS "Apple"
#elif defined(_WIN32) || defined(_WIN64)
#  define BTC_OS_WINDOWS
#  define BTC_OS "Windows"
#else
#  error Cannot determine OS
#endif

// Language
#if defined(__cplusplus)
#  if __cplusplus >= 201703L
#    define BTC_LANG_CPP 17
#    define BTC_LANG_CPP_17
#    define BTC_LANG "C++17"
#  elif __cplusplus >= 201402L
#    define BTC_LANG_CPP 14
#    define BTC_LANG_CPP_14
#    define BTC_LANG "C++14"
#  elif __cplusplus >= 201103L
#    define BTC_LANG_CPP 11
#    define BTC_LANG_CPP_11
#    define BTC_LANG "C++11"
#  else
#    error Unsupported C++ version
#  endif                         // C++ Version
#elif defined(__STDC_VERSION__)  // C
#  if __STDC_VERSION__ >= 201710L
#    define BTC_LANG_C 17
#    define BTC_LANG_C_17
#    define BTC_LANG "C17"
#  elif __STDC_VERSION__ >= 201112L
#    define BTC_LANG_C 11
#    define BTC_LANG_C_11
#    define BTC_LANG "C11"
#  else
#    error Unsupported C version
#  endif  // C Version
#else
#  error Cannot determine C/C++ standard
#endif

// Build Time
#if defined(_BUILD_TIME)
#  define BTC_BUILD_TIME __STRINGIFY_MACRO(_BUILD_TIME)
#else
#  define BTC_BUILD_TIME __DATE__ "T" __TIME__
#endif

// Debug
#if defined(_DEBUG)
#  define BTC_DEBUG
#  define BTC_DEBUG_BUILD 1
#  define BTC_RELEASE_BUILD 0
#else
#  define BTC_RELEASE
#  define BTC_DEBUG_BUILD 0
#  define BTC_RELEASE_BUILD 1
#endif

#endif  // _BTC_CC_PLATFORM_H_
