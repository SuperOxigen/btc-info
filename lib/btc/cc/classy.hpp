// Bitcoin Info - Compiler Helpers - Class Utilities
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_CLASSY_HPP_
#define _BTC_CC_CLASSY_HPP_

#include "btc/cc/platform.h"

static_assert(BTC_LANG_CPP >= 11, "Requires C++11 or newer");

// Macros for easily disabling copying and moving.

#define BTC_DISALLOW_COPY(ClassName)     \
  ClassName(const ClassName &) = delete; \
  ClassName &operator=(const ClassName &) = delete

#define BTC_DISALLOW_MOVE(ClassName) \
  ClassName(ClassName &&) = delete;  \
  ClassName &operator=(ClassName &&) = delete

#define BTC_DISALLOW_COPY_AND_MOVE(ClassName) \
  BTC_DISALLOW_COPY(ClassName);               \
  BTC_DISALLOW_MOVE(ClassName)

// Macros for easily specifying default copy and move operators.

#define BTC_DEFAULT_COPY(ClassName)       \
  ClassName(const ClassName &) = default; \
  ClassName &operator=(const ClassName &) = default

#define BTC_DEFAULT_MOVE(ClassName)  \
  ClassName(ClassName &&) = default; \
  ClassName &operator=(ClassName &&) = default

#define BTC_DEFAULT_COPY_AND_MOVE(ClassName) \
  BTC_DEFAULT_COPY(ClassName);               \
  BTC_DEFAULT_MOVE(ClassName)

// Delegate common class type declarations.

#define BTC_DELEGATE_MUTABLE_ITERATORS(member) \
  using iterator = decltype(member)::iterator; \
  iterator begin() {                           \
    return member.begin();                     \
  }                                            \
  iterator end() {                             \
    return member.end();                       \
  }

#define BTC_DELEGATE_CONST_ITERATORS(member)               \
  using const_iterator = decltype(member)::const_iterator; \
  const_iterator begin() const {                           \
    return member.begin();                                 \
  }                                                        \
  const_iterator end() const {                             \
    return member.end();                                   \
  }                                                        \
  const_iterator cbegin() const {                          \
    return member.cbegin();                                \
  }                                                        \
  const_iterator cend() const {                            \
    return member.cend();                                  \
  }

#define BTC_DELEGATE_ITERATORS(member)    \
  BTC_DELEGATE_MUTABLE_ITERATORS(member); \
  BTC_DELEGATE_CONST_ITERATORS(member)

#define BTC_DELEGATE_ITERATOR_TYPES(member)    \
  using iterator = decltype(member)::iterator; \
  using const_iterator = decltype(member)::const_iterator

#define BTC_DELEGATE_MUTABLE_REVERSE_ITERATORS(member)         \
  using reverse_iterator = decltype(member)::reverse_iterator; \
  reverse_iterator rbegin() {                                  \
    return member.rbegin();                                    \
  }                                                            \
  reverse_iterator rend() {                                    \
    return member.rend();                                      \
  }

#define BTC_DELEGATE_CONST_REVERSE_ITERATORS(member)                       \
  using const_reverse_iterator = decltype(member)::const_reverse_iterator; \
  const_reverse_iterator rbegin() const {                                  \
    return member.rbegin();                                                \
  }                                                                        \
  const_reverse_iterator rend() const {                                    \
    return member.rend();                                                  \
  }                                                                        \
  const_reverse_iterator crbegin() const {                                 \
    return member.crbegin();                                               \
  }                                                                        \
  const_reverse_iterator crend() const {                                   \
    return member.crend();                                                 \
  }

#define BTC_DELEGATE_REVERSE_ITERATORS(member)    \
  BTC_DELEGATE_MUTABLE_REVERSE_ITERATORS(member); \
  BTC_DELEGATE_CONST_REVERSE_ITERATORS(member)

// Equatable

// Helper macro.  Used within class definition which has an Equals()
// method for the type specified in the parameters.
//    bool Equals(const Type &other) const;
#define BTC_EQUATABLE_TO(Type)               \
  bool operator==(const Type &other) const { \
    return Equals(other);                    \
  }                                          \
  bool operator!=(const Type &other) const { \
    return !Equals(other);                   \
  }
// Similar to the above, but for templated classes which can be compared
// to another templated class Type
//    template <typename T>
//    bool Equals(const Type<T> &other) const;
#define BTC_TEMPLATED_EQUATABLE_TO(Type)          \
  template<typename _TT>                          \
  bool operator==(const Type<_TT> &other) const { \
    return Equals(other);                         \
  }                                               \
  template<typename _TT>                          \
  bool operator!=(const Type<_TT> &other) const { \
    return !Equals(other);                        \
  }

// Comparable

// Helper macro.  Used within class definition which has an Compare()
// method for the type specified in the parameters.  Only implements
// no-equatable comparisons.
//    int Compare(const Type &other) const;
#define BTC_COMPARABLE_TO(Type)              \
  bool operator<(const Type &other) const {  \
    return Compare(other) < 0;               \
  }                                          \
  bool operator<=(const Type &other) const { \
    return Compare(other) <= 0;              \
  }                                          \
  bool operator>=(const Type &other) const { \
    return Compare(other) >= 0;              \
  }                                          \
  bool operator>(const Type &other) const {  \
    return Compare(other) > 0;               \
  }

#define BTC_FULLY_COMPARABLE_TO(Type)        \
  BTC_COMPARABLE_TO(type)                    \
  bool operator==(const Type &other) const { \
    return Compare(other) == 0;              \
  }                                          \
  bool operator!=(const Type &other) const { \
    return Compare(other) != 0;              \
  }

// Similar to BTC_COMPARABLE_TO, but for templated classes which can
// be compared to another templated class Type
//    template <typename T>
//    int Compare(const Type<T> &other) const;
#define BTC_TEMPLATED_COMPARABLE_TO(Type)         \
  template<typename _TT>                          \
  bool operator<(const Type<_TT> &other) const {  \
    return Compare(other) < 0;                    \
  }                                               \
  template<typename _TT>                          \
  bool operator<=(const Type<_TT> &other) const { \
    return Compare(other) <= 0;                   \
  }                                               \
  template<typename _TT>                          \
  bool operator>=(const Type<_TT> &other) const { \
    return Compare(other) >= 0;                   \
  }                                               \
  template<typename _TT>                          \
  bool operator>(const Type<_TT> &other) const {  \
    return Compare(other) > 0;                    \
  }

#define BTC_TEMPLATED_FULLY_COMPARABLE_TO(Type)   \
  BTC_TEMPLATED_COMPARABLE_TO(Type)               \
  bool operator==(const Type<_TT> &other) const { \
    return Compare(other) == 0;                   \
  }                                               \
  template<typename _TT>                          \
  bool operator!=(const Type<_TT> &other) const { \
    return Compare(other) != 0;                   \
  }

#endif  // _BTC_CC_CLASSY_HPP_
