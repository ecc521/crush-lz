# Compiler flags and source lists shared by everything that builds C here.

CRUSHLZFSE_CSRC := $(HARNESS_ROOT)/../crates/crushlzfse/csrc
LZBITMAP_CSRC   := $(HARNESS_ROOT)/../crates/lzbitmap/csrc
LZ4_CSRC        := $(HARNESS_ROOT)/../crates/crushlz4/csrc
LZMESH_CSRC     := $(HARNESS_ROOT)/../crates/lzmesh/csrc
CORE            := $(HARNESS_ROOT)/core

CC ?= cc

BASE_CFLAGS := -O3 -std=gnu99 -Wall -Wextra -fno-strict-aliasing -DNDEBUG \
               -I$(CRUSHLZFSE_CSRC) -I$(LZBITMAP_CSRC) -I$(LZ4_CSRC) -I$(LZMESH_CSRC) -I$(CORE)

# x86-64 builds target Haswell (x86-64-v3: AVX2, BMI1/2, FMA, LZCNT, MOVBE),
# which every Intel Mac macOS still supports has. lzbitmap's vector paths
# and lzfse's BMI2 decode loops then need no run-time dispatch. Kept as its
# own variable because the sanitizer builds need the identical set: they
# used to omit it, which had ASan, UBSan and TSan exercising a fallback
# rather than the code that ships. Pre-Haswell hardware builds with
# ISA_CFLAGS= and -DCRUSH_SIMD_PORTABLE.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),x86_64)
    ARCH_CFLAGS ?= -arch x86_64
  endif
endif
BASE_CFLAGS += $(ARCH_CFLAGS)

# Probe whether the compiler with current flags targets x86_64
TARGET_IS_X86 := $(shell $(CC) $(BASE_CFLAGS) $(CFLAGS) -dM -E - < /dev/null 2>/dev/null | grep -c '__x86_64__')
ifeq ($(TARGET_IS_X86),1)
  ISA_CFLAGS := -march=x86-64-v3
else
  ISA_CFLAGS :=
endif
BASE_CFLAGS += $(ISA_CFLAGS)

CODEC_SRCS := \
  $(CRUSHLZFSE_CSRC)/lzfse_encode.c \
  $(CRUSHLZFSE_CSRC)/lzfse_encode_base.c \
  $(CRUSHLZFSE_CSRC)/lzfse_decode.c \
  $(CRUSHLZFSE_CSRC)/lzfse_decode_base.c \
  $(CRUSHLZFSE_CSRC)/lzvn_encode_base.c \
  $(CRUSHLZFSE_CSRC)/lzvn_decode_base.c \
  $(CRUSHLZFSE_CSRC)/lzfse_fse.c \
  $(CRUSHLZFSE_CSRC)/crushlzfse.c \
  $(CRUSHLZFSE_CSRC)/crushlzvn.c \
  $(LZBITMAP_CSRC)/libzbitmap.c \
  $(LZMESH_CSRC)/crushlzmesh.c \
  $(LZ4_CSRC)/crushlz4.c \
  $(LZ4_CSRC)/vendor/lz4/lz4.c \
  $(LZ4_CSRC)/vendor/lz4/lz4hc.c

CORE_SRCS := $(CORE)/engines.c $(CORE)/oracle.c

# lzfse_encode_base.c calls log2(), and Linux needs -lm for that.
LIBS := -lm

# Apple's libcompression, linked only into the programs that compare against it.
ifeq ($(UNAME_S),Darwin)
  APPLE_LIBS := -lcompression
else
  APPLE_LIBS :=
endif

# Reference codecs the engine registry links; optional ones leave an inactive
# row in the engine table when absent.
ENGINE_LIBS := -lz $(APPLE_LIBS)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(TARGET_IS_X86),1)
    HOMEBREW_PREFIX ?= $(shell if [ -d /usr/local/include ]; then echo /usr/local; else echo /opt/homebrew-not-x86; fi)
  else
    HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
  endif
else
  HOMEBREW_PREFIX ?= /usr
endif
ZSTD_PREFIX ?= $(HOMEBREW_PREFIX)
ifneq ($(wildcard $(ZSTD_PREFIX)/include/zstd.h),)
  BASE_CFLAGS += -DHAVE_ZSTD -I$(ZSTD_PREFIX)/include
  ENGINE_LIBS += -L$(ZSTD_PREFIX)/lib -lzstd
endif

ZOPFLI_PREFIX ?= $(HOMEBREW_PREFIX)
ifneq ($(wildcard $(ZOPFLI_PREFIX)/include/zopfli.h),)
  BASE_CFLAGS += -DHAVE_ZOPFLI -I$(ZOPFLI_PREFIX)/include
  ENGINE_LIBS += -L$(ZOPFLI_PREFIX)/lib -lzopfli
endif
