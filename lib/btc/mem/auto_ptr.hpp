// Bitcoin Info - Memory - Auto Pointer
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CC_AUTO_PTR_H_
#define _BTC_CC_AUTO_PTR_H_

#include <functional>
#include <type_traits>

#include "btc/cc/classy.hpp"

namespace btc {
namespace mem {
// AutoPointer - Wrapper for C pointers with custom destructors.
//
// When the AutoPointer goes out of scope, the pointer will be
// freed by the provided Destructor.
// Provides accessors similar to std::unique_ptr.
template<typename Type, void (*Destructor)(Type *)>
class AutoPointer {
public:
  using PointerType = typename std::add_pointer<Type>::type;
  using ElementType = Type;

  BTC_DISALLOW_COPY(AutoPointer);
  AutoPointer() {}
  AutoPointer(std::nullptr_t) {}
  AutoPointer(Type *ptr): _ptr(ptr) {}
  AutoPointer(AutoPointer &&other): _ptr(other.Release()) {}

  ~AutoPointer() { Reset(); }

  AutoPointer &operator=(AutoPointer &&other) {
    Reset(other.Release());
    return *this;
  }
  AutoPointer &operator=(std::nullptr_t) {
    Reset();
    return *this;
  }

  bool IsNull() const { return _ptr == nullptr; }
  bool IsSet() const { return _ptr != nullptr; }
  explicit operator bool() const { return IsSet(); }

  Type &operator*() { return *_ptr; }
  const Type &operator*() const { return *_ptr; }
  Type *operator->() { return _ptr; }
  const Type *operator->() const { return _ptr; }

  const Type *Get() const { return _ptr; }
  Type *Get() { return _ptr; }

  Type *Release() {
    Type *ptr = _ptr;
    _ptr = nullptr;
    return ptr;
  }

  void Swap(AutoPointer &other) { std::swap(_ptr, other._ptr); }

  void Reset() {
    if (IsSet()) Destructor(_ptr);
    _ptr = nullptr;
  }
  void Reset(Type *ptr) {
    Reset();
    _ptr = ptr;
  }

  size_t Hash() const { return std::hash<Type *>()(_ptr); }

  bool operator==(const AutoPointer &other) const { return _ptr == other._ptr; }
  bool operator==(Type *ptr) const { return _ptr == ptr; }
  bool operator==(const Type *ptr) const { return _ptr == ptr; }
  bool operator==(std::nullptr_t) const { return IsNull(); }

private:
  Type *_ptr = nullptr;
};  // class AutoPointer.
}  // namespace mem
}  // namespace btc

template<typename Type, void (*Destructor)(Type *)>
struct std::hash<btc::mem::AutoPointer<Type, Destructor>> {
  std::size_t operator()(
      const btc::mem::AutoPointer<Type, Destructor> &ptr) const {
    return ptr.Hash();
  }
};  // struct std::hash

#endif  // _BTC_CC_AUTO_PTR_H_
