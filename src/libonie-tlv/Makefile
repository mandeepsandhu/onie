#
# Copyright (C) 2015 Mandeep Sandhu <mandeep.sandhu@cyaninc.com>
#
# SPDX-License-Identifier:     GPL-2.0
#

PKG_NAME := libonie-tlv
TARGET   := $(PKG_NAME).a
SUMMARY  := A library for reading/writing ONIE TLV data.

SRC := onie-tlv.c

OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)

HIDE     	:= @
CC       	:= gcc
INCLUDES 	:=
CFLAGS   	:= -g -Wall
BUILD_DIR 	:= ../../build/$(PKG_NAME)

ifeq (,$(strip $(filter $(MAKECMDGOALS),clean)))
	MAKEFLAGS+=--output-sync=target
	ifneq (,$(strip $(DEP)))
		-include $(DEP)
	endif
endif

# Implicit rules:
$(BUILD_DIR)/%.o : %.c
	@printf "%b[1;36m%s%b[0m\n" "\0033" "Compiling: $< -> $@" "\0033"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
	@printf "\n"

$(BUILD_DIR)/%.d : %.c
	@printf "%b[1;36m%s%b[0m\n" "\0033" "Dependency: $< -> $@" "\0033"
	$(CC) -MM -MG -MT '$@ $(@:.d=.o)' $(CFLAGS) $(INCLUDES) -o $@ $<
	@printf "\n"


# Make all
.PHONY: all make_target_dir
.DEFAULT_GOAL := all
all: make_target_dir $(BUILD_DIR)/$(TARGET)
make_target_dir: $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@

# TARGET
$(BUILD_DIR)/$(TARGET): $(BUILD_DIR)/$(OBJ) $(BUILD_DIR)/$(DEP) Makefile
	@printf "%b[1;36m%s%b[0m\n" "\0033" "Linking: $(OBJ) -> $@" "\0033"
	ar -crs $@ $(BUILD_DIR)/$(OBJ)
	@printf "%b[1;32m%s%b[0m\n\n" "\0033" "$@ Done!" "\0033"


# Clean:
RM_LIST = $(wildcard $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d)
.PHONY: clean
clean:
	@printf "%b[1;36m%s%b[0m\n" "\0033" "Cleaning" "\0033"
ifneq (,$(RM_LIST))
	rm -rf $(RM_LIST)
	@printf "\n"
endif
	@printf "%b[1;32m%s%b[0m\n\n" "\0033" "Done!" "\0033"
