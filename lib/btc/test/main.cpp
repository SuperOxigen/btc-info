// Bitcoin Info - Test - Core Test Main
//
// Copyright (c) 2022 Alex Dale
// This project is licensed under the terms of the MIT license.
// See LICENSE for details.
#include <iostream>

#include <gtest/gtest.h>

#include "btc/cc/platform.h"

namespace {
void PrintBuildInfo() {
  std::cout << "CC: " << BTC_CC << std::endl;
  // std::cout << "CC-Version: " << BTC_CC_INFO << std::endl;
  std::cout << "OS: " << BTC_OS << std::endl;
  std::cout << "Lang: " << BTC_LANG << std::endl;
  std::cout << "Build Time: " << BTC_BUILD_TIME << std::endl;
}
}  // namespace

int main(int argc, char **argv) {
  PrintBuildInfo();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
