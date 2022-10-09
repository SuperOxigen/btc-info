// Bitcoin Info - Cryptography - OpenSSL Digester
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#ifndef _BTC_CRYPTO_OPENSSL_DIGESTER_HPP_
#define _BTC_CRYPTO_OPENSSL_DIGESTER_HPP_

#ifndef _BTC_CRYPTO_DIGESTER_INTERNAL_
#  error Header should only be included internally
#endif  // _BTC_CRYPTO_DIGESTER_INTERNAL_

#include <memory>
#include <vector>

#include <openssl/evp.h>

#include "btc/cc/attr.h"
#include "btc/cc/base.h"
#include "btc/cc/classy.hpp"
#include "btc/crypto/digest.hpp"
#include "btc/mem/auto_ptr.hpp"

namespace btc {
namespace crypto {
namespace internal {
using EvpMdCtxPointer = btc::mem::AutoPointer<EVP_MD_CTX, EVP_MD_CTX_free>;

class NativeDigester {
public:
  BTC_DISALLOW_COPY_AND_MOVE(NativeDigester);
  ~NativeDigester() {}

  static std::unique_ptr<NativeDigester> New() {
    std::unique_ptr<NativeDigester> digester(new NativeDigester());
    if (!digester->Init()) {
      digester.reset();
    }
    return digester;
  }

  EVP_MD_CTX *ctx() { return _ctx.Get(); }
  const EVP_MD_CTX *ctx() const { return _ctx.Get(); }

  bool Reset();
  bool Update(const uint8_t *data, size_t data_size) __NOT_NULL(2);
  bool Finalize(uint8_t *digest) __NOT_NULL(2);

private:
  NativeDigester() {}

  bool Init();

  bool Save();
  bool Restore();

  EvpMdCtxPointer _ctx = nullptr;
  EvpMdCtxPointer _backup_ctx = nullptr;
  bool _ready = false;
  bool _has_backup = false;
};  // class NativeDigester
}  // namespace internal
}  // namespace crypto
}  // namespace btc

#endif  // _BTC_CRYPTO_OPENSSL_DIGESTER_HPP_
