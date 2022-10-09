# Bitcoin Info - Makefile
#
# Copyright (c) 2022 Alex Dale
# This project is licensed under the terms of the MIT license.
# See LICENSE for details.

# == System Information ==

ARCH := $(shell uname -m)
OS := $(shell uname -s)

# == Build Information ==

BUILD_TIME := $(shell date --iso-8601=seconds)

$(info [INFO] Build time: $(BUILD_TIME))
$(info [INFO] Arch: $(ARCH))
$(info [INFO] OS: $(OS))

# == Directories ==

BUILD_DIR := out/debug
OBJ_DIR := $(BUILD_DIR)/obj
LIB_DIR := $(BUILD_DIR)/lib
TEST_OBJ_DIR := $(OBJ_DIR)/test
BIN_DIR := $(BUILD_DIR)/bin

# == Compiler Flags ==

AR := ar
C_CC := gcc
CPP_CC := g++

INFO_FLAGS := -D_ARCH=$(ARCH) -D_OS=$(OS) -D_BUILD_TIME=$(BUILD_TIME)

DEBUG_FLAGS := -g -D_DEBUG
RELEASE_FLAGS := -Werror
COMMON_FLAGS := -Wall -Wextra -mcpu=native -mtune=native $(INFO_FLAGS) -Ilib/ -L$(LIB_DIR)

FLAGS := $(DEBUG_FLAGS) $(COMMON_FLAGS)

C_FLAGS := -std=c17 $(FLAGS)
CPP_FLAGS := -std=c++17 -Weffc++ $(FLAGS)

# == Default Targets ==

.PHONY: all core tests clean

all: core

core: $(LIB_DIR)/libbtc.a

test: $(BIN_DIR)/btc.test.exe

clean:
	@echo "[ RM ] $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

# == Core Objects ==

CORE_OBJS :=

$(OBJ_DIR)/btc.log.o: lib/btc/src/log.c lib/btc/log.h
	@echo "[ CC ] $@"
	@mkdir -p $(OBJ_DIR)
	@$(C_CC) $(C_FLAGS) -o $@ -c lib/btc/src/log.c

CORE_OBJS += $(OBJ_DIR)/btc.log.o

# Encoders

$(OBJ_DIR)/btc.encode.hex.o: lib/btc/encode/src/hex.cpp lib/btc/encode/hex.hpp
	@echo "[ CX ] $@"
	@mkdir -p $(OBJ_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ -c lib/btc/encode/src/hex.cpp

CORE_OBJS += $(OBJ_DIR)/btc.encode.hex.o

# Cryptography

$(OBJ_DIR)/btc.crypto.digest.o: lib/btc/crypto/src/digest.cpp lib/btc/crypto/src/digest.openssl.cpp lib/btc/crypto/digest.hpp
	@mkdir -p $(OBJ_DIR)
	@echo "[ CX ] $(OBJ_DIR)/btc.crypto.digest.openssl.o"
	@$(CPP_CC) $(CPP_FLAGS) -o $(OBJ_DIR)/btc.crypto.digest.openssl.o -c lib/btc/crypto/src/digest.openssl.cpp
	@echo "[ CX ] $(OBJ_DIR)/btc.crypto.digest.common.o"
	@$(CPP_CC) $(CPP_FLAGS) -o $(OBJ_DIR)/btc.crypto.digest.common.o -c lib/btc/crypto/src/digest.cpp
	@echo "[ LD ] $@"
	@ld -relocatable $(OBJ_DIR)/btc.crypto.digest.*.o -o $@

CORE_OBJS += $(OBJ_DIR)/btc.crypto.digest.o

$(OBJ_DIR)/btc.crypto.ecc_key.o: lib/btc/crypto/src/ecc_key.openssl.cpp lib/btc/crypto/ecc_key.hpp
	@mkdir -p $(OBJ_DIR)
	@echo "[ CX ] $(OBJ_DIR)/btc.crypto.ecc_key.o"
	@$(CPP_CC) $(CPP_FLAGS) -o $(OBJ_DIR)/btc.crypto.ecc_key.o -c lib/btc/crypto/src/ecc_key.openssl.cpp

CORE_OBJS += $(OBJ_DIR)/btc.crypto.ecc_key.o

$(OBJ_DIR)/btc.crypto.digester.o: lib/btc/crypto/src/digester.openssl.cpp lib/btc/crypto/digester.hpp
	@mkdir -p $(OBJ_DIR)
	@echo "[ CX ] $(OBJ_DIR)/btc.crypto.digester.o"
	@$(CPP_CC) $(CPP_FLAGS) -o $(OBJ_DIR)/btc.crypto.digester.o -c lib/btc/crypto/src/digester.openssl.cpp

CORE_OBJS += $(OBJ_DIR)/btc.crypto.digester.o

# == Core Library ==

$(LIB_DIR)/libbtc.a: $(CORE_OBJS)
	@echo "[ AR ] $@"
	@rm -f $@
	@mkdir -p $(LIB_DIR)
	@$(AR) rsc $@ $(CORE_OBJS)

# == Core Test Objects ==

CORE_TEST_OBJS =

$(TEST_OBJ_DIR)/btc.encode.hex.o: lib/btc/encode/test/hex.test.cpp lib/btc/encode/hex.hpp
	@echo "[ CX ] $@"
	@mkdir -p $(TEST_OBJ_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ -c lib/btc/encode/test/hex.test.cpp

CORE_TEST_OBJS += $(TEST_OBJ_DIR)/btc.encode.hex.o

$(TEST_OBJ_DIR)/btc.crypto.digest.o: lib/btc/crypto/test/digest.test.cpp lib/btc/crypto/digest.hpp
	@echo "[ CX ] $@"
	@mkdir -p $(TEST_OBJ_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ -c lib/btc/crypto/test/digest.test.cpp

CORE_TEST_OBJS += $(TEST_OBJ_DIR)/btc.crypto.digest.o

$(TEST_OBJ_DIR)/btc.crypto.ecc_key.o: lib/btc/crypto/test/ecc_key.test.cpp lib/btc/crypto/ecc_key.hpp
	@echo "[ CX ] $@"
	@mkdir -p $(TEST_OBJ_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ -c lib/btc/crypto/test/ecc_key.test.cpp

CORE_TEST_OBJS += $(TEST_OBJ_DIR)/btc.crypto.ecc_key.o

$(TEST_OBJ_DIR)/btc.crypto.digester.o: lib/btc/crypto/test/digester.test.cpp lib/btc/crypto/digester.hpp
	@echo "[ CX ] $@"
	@mkdir -p $(TEST_OBJ_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ -c lib/btc/crypto/test/digester.test.cpp

CORE_TEST_OBJS += $(TEST_OBJ_DIR)/btc.crypto.digester.o

# == Core Test Executable ==

$(BIN_DIR)/btc.test.exe: $(LIB_DIR)/libbtc.a lib/btc/test/main.cpp $(CORE_TEST_OBJS)
	@echo "[ CX ] $@"
	@mkdir -p $(BIN_DIR)
	@$(CPP_CC) $(CPP_FLAGS) -o $@ lib/btc/test/main.cpp $(CORE_TEST_OBJS) -lbtc -lcrypto -lgtest
