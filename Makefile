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
COMMON_FLAGS := -Wall -Wextra -mcpu=native -mtune=native $(INFO_FLAGS) -Ilib/

FLAGS := $(DEBUG_FLAGS) $(COMMON_FLAGS)

C_FLAGS := -std=c17 $(FLAGS)
CPP_FLAGS := -std=c++17 -Weffc++ $(FLAGS)

# == Default Targets ==

.PHONY: all core tests clean

all: core

core: $(LIB_DIR)/btc.a

test: all

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

# == Core Library ==

$(LIB_DIR)/btc.a: $(CORE_OBJS)
	@echo "[ AR ] $@"
	@rm -f $@
	@mkdir -p $(LIB_DIR)
	@$(AR) rsc $@ $(CORE_OBJS)