HARNESS_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
include $(HARNESS_ROOT)/flags.mk

BUILD  := $(HARNESS_ROOT)/build
CFLAGS := $(BASE_CFLAGS)

.DEFAULT_GOAL := all

CONFORMANCE_SRCS := $(wildcard $(HARNESS_ROOT)/conformance/*.c)
CONFORMANCE_BINS := $(patsubst $(HARNESS_ROOT)/conformance/%.c,$(BUILD)/%,$(CONFORMANCE_SRCS))

# Every codec source and header is a prerequisite of every binary.
CODEC_HDRS := $(wildcard $(CRUSHLZFSE_CSRC)/*.h $(LZBITMAP_CSRC)/*.h $(LZ4_CSRC)/*.h $(LZMESH_CSRC)/*.h $(CORE)/*.h) \
              $(wildcard $(HARNESS_ROOT)/conformance/*.h)
CODEC_DEPS := $(CODEC_SRCS) $(CODEC_HDRS)

# Tests that #include a codec .c file must not also link it.
included_srcs = $(shell grep -o 'include "[a-z_0-9]*\.c"' $(1) 2>/dev/null | sed 's/include "//; s/"//')
codec_srcs_for = $(filter-out $(foreach f,$(call included_srcs,$(1)),%/$(f)),$(CODEC_SRCS))

# Investigation tools, built on request. zbm_apple_probe is macOS only.
PROBE_BINS := $(BUILD)/zbm_sweep $(BUILD)/crushlzfse_sweep $(BUILD)/crushlzvn_sweep \
               $(BUILD)/crushlz4_sweep $(BUILD)/level_table $(BUILD)/zbm_edge_cases
ifeq ($(UNAME_S),Darwin)
  PROBE_BINS += $(BUILD)/zbm_apple_probe
endif
probe: $(PROBE_BINS)

# Sanitizer builds: ASan+UBSan and MSan (Linux clang only) for every test,
# TSan for the threaded ones.
SAN_CFLAGS  := -O1 -g -std=gnu99 -Wall -Wextra -fno-strict-aliasing $(ISA_CFLAGS) \
               -I$(CRUSHLZFSE_CSRC) -I$(LZBITMAP_CSRC) -I$(LZ4_CSRC) -I$(LZMESH_CSRC) -I$(CORE)
ASAN_FLAGS  := -fsanitize=address,undefined -fno-omit-frame-pointer
TSAN_FLAGS  := -fsanitize=thread
MSAN_FLAGS  := -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer

THREADED_SRCS := $(shell grep -l pthread $(HARNESS_ROOT)/conformance/*.c 2>/dev/null)
TSAN_BINS := $(patsubst $(HARNESS_ROOT)/conformance/%.c,$(BUILD)/tsan/%,$(THREADED_SRCS))
ASAN_BINS := $(patsubst $(HARNESS_ROOT)/conformance/%.c,$(BUILD)/asan/%,$(CONFORMANCE_SRCS))
MSAN_BINS := $(patsubst $(HARNESS_ROOT)/conformance/%.c,$(BUILD)/msan/%,$(CONFORMANCE_SRCS))

.PHONY: all bench tests check check-quick asan tsan msan asan-check tsan-check msan-check sanitize fuzz proofs proofs-mutants fixtures probe clean distclean
all: bench tests

bench: $(BUILD)/bench
tests: $(CONFORMANCE_BINS)
asan: $(ASAN_BINS)
tsan: $(TSAN_BINS)
msan: $(MSAN_BINS)
sanitize: asan-check tsan-check

$(BUILD) $(BUILD)/asan $(BUILD)/tsan $(BUILD)/msan:
	@mkdir -p $@

$(BUILD)/bench: $(HARNESS_ROOT)/bench/main.c $(CORE_SRCS) $(CODEC_DEPS) | $(BUILD)
	$(CC) $(CFLAGS) -pthread -o $@ $(filter %.c,$^) $(LIBS) $(ENGINE_LIBS)

# $(APPLE_LIBS) because the crushlzvn_{candidate,dispatch,greedy} tests compare
# against Apple's libcompression under #ifdef __APPLE__; it is empty elsewhere.
$(BUILD)/%: $(HARNESS_ROOT)/conformance/%.c $(CODEC_DEPS) | $(BUILD)
	$(CC) $(CFLAGS) -pthread -o $@ $< $(call codec_srcs_for,$<) $(LIBS) $(APPLE_LIBS)

# zbm_decoder_diff_test links libzbitmap.c twice: once as shipped, once with
# the decoder's fast paths disabled and every public symbol renamed. Every
# public symbol in crushlzbitmap.h must appear in ZBM_RENAME or the link fails.
# $(1) is the output, $(2) the extra flags.
ZBM_RENAME := $(foreach s,crushlzbitmap_params_for_level crushlzbitmap_default_params \
                          crushlzbitmap_get_capabilities \
                          crushlzbitmap_scratch_size crushlzbitmap_encode_bound \
                          crushlzbitmap_encode_buffer crushlzbitmap_encode_buffer_advanced \
                          crushlzbitmap_encode_chunk crushlzbitmap_decode_buffer,-D$(s)=ref_$(s))

define BUILD_DIFF_TEST
	$(CC) $(2) -DZBM_TEST_DECODER_FALLBACK $(ZBM_RENAME) \
	      -c $(LZBITMAP_CSRC)/libzbitmap.c -o $(1).fallback.o
	$(CC) $(2) -c $(LZBITMAP_CSRC)/libzbitmap.c -o $(1).normal.o
	$(CC) $(2) -o $(1) $(HARNESS_ROOT)/conformance/zbm_decoder_diff_test.c \
	      $(1).normal.o $(1).fallback.o $(LIBS)
endef

$(BUILD)/zbm_decoder_diff_test: $(HARNESS_ROOT)/conformance/zbm_decoder_diff_test.c \
                                $(CODEC_DEPS) | $(BUILD)
	$(call BUILD_DIFF_TEST,$@,$(CFLAGS))

$(BUILD)/asan/zbm_decoder_diff_test: $(HARNESS_ROOT)/conformance/zbm_decoder_diff_test.c \
                                     $(CODEC_DEPS) | $(BUILD)/asan
	$(call BUILD_DIFF_TEST,$@,$(SAN_CFLAGS) $(ASAN_FLAGS))

$(BUILD)/msan/zbm_decoder_diff_test: $(HARNESS_ROOT)/conformance/zbm_decoder_diff_test.c \
                                     $(CODEC_DEPS) | $(BUILD)/msan
	$(call BUILD_DIFF_TEST,$@,$(SAN_CFLAGS) $(MSAN_FLAGS))

# zbm_simd_diff_test links libzbitmap.c twice: once as shipped (whatever
# vector path the host provides), once with CRUSH_SIMD_PORTABLE forced and
# every public symbol renamed. The portable object drops -march=x86-64-v3
# from its own flags (even though CRUSH_SIMD_PORTABLE alone is
# enough to select the scalar branch, see libzbitmap.c) so this build proves
# the portable branch really needs no ISA extension, not just that it wins
# when one happens to be present. $(1) is the output, $(2) the extra flags.
ZBM_SIMD_RENAME := $(foreach s,crushlzbitmap_params_for_level crushlzbitmap_default_params \
                          crushlzbitmap_get_capabilities \
                          crushlzbitmap_scratch_size crushlzbitmap_encode_bound \
                          crushlzbitmap_encode_buffer crushlzbitmap_encode_buffer_advanced \
                          crushlzbitmap_encode_chunk crushlzbitmap_decode_buffer,-D$(s)=portable_$(s))

define BUILD_SIMD_DIFF_TEST
	$(CC) $(filter-out -march=x86-64-v3,$(2)) -DCRUSH_SIMD_PORTABLE $(ZBM_SIMD_RENAME) \
	      -c $(LZBITMAP_CSRC)/libzbitmap.c -o $(1).portable.o
	$(CC) $(2) -c $(LZBITMAP_CSRC)/libzbitmap.c -o $(1).vector.o
	$(CC) $(2) -o $(1) $(HARNESS_ROOT)/conformance/zbm_simd_diff_test.c \
	      $(1).vector.o $(1).portable.o $(LIBS)
endef

$(BUILD)/zbm_simd_diff_test: $(HARNESS_ROOT)/conformance/zbm_simd_diff_test.c \
                             $(CODEC_DEPS) | $(BUILD)
	$(call BUILD_SIMD_DIFF_TEST,$@,$(CFLAGS))

$(BUILD)/asan/zbm_simd_diff_test: $(HARNESS_ROOT)/conformance/zbm_simd_diff_test.c \
                                  $(CODEC_DEPS) | $(BUILD)/asan
	$(call BUILD_SIMD_DIFF_TEST,$@,$(SAN_CFLAGS) $(ASAN_FLAGS))

$(BUILD)/msan/zbm_simd_diff_test: $(HARNESS_ROOT)/conformance/zbm_simd_diff_test.c \
                                  $(CODEC_DEPS) | $(BUILD)/msan
	$(call BUILD_SIMD_DIFF_TEST,$@,$(SAN_CFLAGS) $(MSAN_FLAGS))

$(BUILD)/asan/%: $(HARNESS_ROOT)/conformance/%.c $(CODEC_DEPS) | $(BUILD)/asan
	$(CC) $(SAN_CFLAGS) $(ASAN_FLAGS) -pthread -o $@ $< $(call codec_srcs_for,$<) $(LIBS) $(APPLE_LIBS)

$(BUILD)/tsan/%: $(HARNESS_ROOT)/conformance/%.c $(CODEC_DEPS) | $(BUILD)/tsan
	$(CC) $(SAN_CFLAGS) $(TSAN_FLAGS) -pthread -o $@ $< $(call codec_srcs_for,$<) $(LIBS) $(APPLE_LIBS)

$(BUILD)/msan/%: $(HARNESS_ROOT)/conformance/%.c $(CODEC_DEPS) | $(BUILD)/msan
	$(CC) $(SAN_CFLAGS) $(MSAN_FLAGS) -pthread -o $@ $< $(call codec_srcs_for,$<) $(LIBS)

FIXTURE_DIR := $(BUILD)/fixtures
FIXTURE_MANIFEST := $(FIXTURE_DIR)/manifest.txt

# Committed LZBITMAP fixtures (NNN-original / NNN-compressed pairs).
ZBM_FIXTURE_DIR := $(HARNESS_ROOT)/conformance/zbm_fixtures
ZBM_OUTPUT_DIR  := $(BUILD)/zbm_out

# Fixture size; empty lets make_fixtures scale to the core count.
FIXTURE_BYTES ?=

# Levels zbm_decoder_diff_test sweeps, comma-separated; empty means all.
ZBM_DIFF_LEVELS ?=

fixtures: $(FIXTURE_MANIFEST)

$(FIXTURE_MANIFEST): $(HARNESS_ROOT)/tools/make_fixtures.c | $(BUILD)
	@mkdir -p $(FIXTURE_DIR)
	@$(CC) $(CFLAGS) -o $(BUILD)/make_fixtures $<
	@$(BUILD)/make_fixtures $(FIXTURE_DIR) $(FIXTURE_BYTES) >/dev/null

NCPU := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
RUN_TESTS := $(HARNESS_ROOT)/tools/run_tests.sh

# Builds with -j$(NCPU), then runs every test on $(NCPU) workers.
check:
	@$(MAKE) --no-print-directory -j$(NCPU) all $(FIXTURE_MANIFEST)
	@mkdir -p $(ZBM_OUTPUT_DIR)
	@ZBM_FIXTURE_DIR="$(ZBM_FIXTURE_DIR)" ZBM_OUTPUT_DIR="$(ZBM_OUTPUT_DIR)" \
	  ZBM_DIFF_LEVELS="$(ZBM_DIFF_LEVELS)" MANIFEST=$(FIXTURE_MANIFEST) FIXDIR=$(FIXTURE_DIR) \
	  JOBS=$(NCPU) $(RUN_TESTS) $(BUILD)/.logs $(CONFORMANCE_BINS) \
	  && echo "all conformance tests passed" || { echo "FAILURES"; exit 1; }

# Same suite with small fixtures and a subset of the decoder-differential sweep.
check-quick:
	@$(MAKE) --no-print-directory -C $(HARNESS_ROOT) check FIXTURE_BYTES=262144 \
	    ZBM_DIFF_LEVELS=-4,-2,0,6,7,10

# ASan gets the smallest fixture set; coverage uses it too. The sanitizer
# runs use a set sized from the core count, since their concurrency tests run
# at full width.
ASAN_FIXTURE_DIR := $(BUILD)/asan-fixtures
ASAN_FIXTURE_MANIFEST := $(ASAN_FIXTURE_DIR)/manifest.txt
SAN_FIXTURE_DIR := $(BUILD)/san-fixtures
SAN_FIXTURE_MANIFEST := $(SAN_FIXTURE_DIR)/manifest.txt

$(ASAN_FIXTURE_MANIFEST): $(HARNESS_ROOT)/tools/make_fixtures.c | $(BUILD)
	@mkdir -p $(ASAN_FIXTURE_DIR)
	@$(CC) $(CFLAGS) -o $(BUILD)/make_fixtures_asan $(filter %.c,$^)
	@$(BUILD)/make_fixtures_asan $(ASAN_FIXTURE_DIR) 131072 >/dev/null

$(SAN_FIXTURE_MANIFEST): $(HARNESS_ROOT)/tools/make_fixtures.c | $(BUILD)
	@mkdir -p $(SAN_FIXTURE_DIR)
	@$(CC) $(CFLAGS) -o $(BUILD)/make_fixtures_san $(filter %.c,$^)
	@$(BUILD)/make_fixtures_san $(SAN_FIXTURE_DIR) >/dev/null

# DIR's tests on JOBS workers. Arguments and environment match `check`.
JOBS ?= $(NCPU)
.PHONY: run-san
run-san:
	@mkdir -p $(DIR)/zbm_out
	@ZBM_FIXTURE_DIR="$(ZBM_FIXTURE_DIR)" ZBM_OUTPUT_DIR="$(DIR)/zbm_out" \
	  ZBM_DIFF_LEVELS="$(ZBM_DIFF_LEVELS)" MANIFEST=$(SAN_FIXTURE_MANIFEST) FIXDIR=$(SAN_FIXTURE_DIR) \
	  SAN=1 JOBS=$(JOBS) $(RUN_TESTS) $(DIR)/.logs $(BINS) \
	  && echo "clean ($(JOBS) at a time)" || { echo "SANITIZER FAILURES"; exit 1; }

asan-check:
	@$(MAKE) --no-print-directory -j$(NCPU) asan $(SAN_FIXTURE_MANIFEST)
	@$(MAKE) --no-print-directory run-san DIR=$(BUILD)/asan BINS="$(ASAN_BINS)"

msan-check:
	@$(MAKE) --no-print-directory -j$(NCPU) msan $(SAN_FIXTURE_MANIFEST)
	@$(MAKE) --no-print-directory run-san DIR=$(BUILD)/msan BINS="$(MSAN_BINS)"

# TSan runs one binary at a time: each one already uses every core.
tsan-check:
	@$(MAKE) --no-print-directory -j$(NCPU) tsan $(SAN_FIXTURE_MANIFEST)
	@$(MAKE) --no-print-directory run-san DIR=$(BUILD)/tsan BINS="$(TSAN_BINS)" JOBS=1

# Line coverage of the codec sources under the conformance suite.
COV_DIR   := $(BUILD)/coverage
COV_FLAGS := -fprofile-instr-generate -fcoverage-mapping
COV_BINS  := $(patsubst $(HARNESS_ROOT)/conformance/%.c,$(COV_DIR)/%,$(CONFORMANCE_SRCS))
PROFDATA  := $(shell xcrun --find llvm-profdata 2>/dev/null || command -v llvm-profdata)
LLVMCOV   := $(shell xcrun --find llvm-cov 2>/dev/null || command -v llvm-cov)

$(COV_DIR):
	@mkdir -p $@

$(COV_DIR)/zbm_decoder_diff_test: $(HARNESS_ROOT)/conformance/zbm_decoder_diff_test.c \
                                  $(CODEC_DEPS) | $(COV_DIR)
	$(call BUILD_DIFF_TEST,$@,$(SAN_CFLAGS) $(COV_FLAGS))

$(COV_DIR)/zbm_simd_diff_test: $(HARNESS_ROOT)/conformance/zbm_simd_diff_test.c \
                               $(CODEC_DEPS) | $(COV_DIR)
	$(call BUILD_SIMD_DIFF_TEST,$@,$(SAN_CFLAGS) $(COV_FLAGS))

$(COV_DIR)/%: $(HARNESS_ROOT)/conformance/%.c $(CODEC_DEPS) | $(COV_DIR)
	$(CC) $(SAN_CFLAGS) $(COV_FLAGS) -pthread -o $@ $< $(call codec_srcs_for,$<) $(LIBS)

.PHONY: coverage
coverage: $(COV_BINS) $(ASAN_FIXTURE_MANIFEST)
	@[ -n "$(PROFDATA)" ] && [ -n "$(LLVMCOV)" ] || \
	  { echo "llvm-profdata/llvm-cov not found"; exit 1; }
	@rm -f $(COV_DIR)/*.profraw $(COV_DIR)/merged.profdata
	@mkdir -p $(COV_DIR)/zbm_out
	@for t in $(COV_BINS); do \
	  name=$$(basename $$t); \
	  case "$$name" in \
	    *concurrency*) arg="$(ASAN_FIXTURE_MANIFEST)" ;; \
	    *edge_case*)   arg="$(ASAN_FIXTURE_DIR)/ragged.bin" ;; \
	    *)             arg="" ;; \
	  esac; \
	  LLVM_PROFILE_FILE=$(COV_DIR)/$$name.profraw \
	    ZBM_FIXTURE_DIR="$(ZBM_FIXTURE_DIR)" ZBM_OUTPUT_DIR="$(COV_DIR)/zbm_out" \
	    CRUSHLZ_TEST_THREADS=2 "$$t" $$arg >/dev/null 2>&1 || true; \
	done
	@$(PROFDATA) merge -sparse $(COV_DIR)/*.profraw -o $(COV_DIR)/merged.profdata
	@$(LLVMCOV) report $(foreach b,$(COV_BINS),-object $(b)) \
	    -instr-profile=$(COV_DIR)/merged.profdata \
	    -ignore-filename-regex='harness/(conformance|core|bench)/'
	@echo ""
	@echo "line-by-line: $(LLVMCOV) show -object $(firstword $(COV_BINS)) \\"
	@echo "                -instr-profile=$(COV_DIR)/merged.profdata <source.c>"

fuzz:
	@$(HARNESS_ROOT)/fuzz/build.sh

# CBMC proofs; see proofs/README.md. Needs CBMC >= 6 on PATH.
proofs:
	@$(HARNESS_ROOT)/proofs/run.sh

proofs-mutants:
	@$(HARNESS_ROOT)/proofs/run.sh mutants

$(BUILD)/zbm_apple_probe: $(HARNESS_ROOT)/tools/zbm_apple_probe.c \
                          $(LZBITMAP_CSRC)/libzbitmap.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

# Compares Apple's decoder with ours on macOS; elsewhere prints ours only.
$(BUILD)/zbm_edge_cases: $(HARNESS_ROOT)/tools/zbm_edge_cases.c \
                         $(LZBITMAP_CSRC)/libzbitmap.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

$(BUILD)/zbm_sweep: $(HARNESS_ROOT)/tools/zbm_sweep.c \
                    $(LZBITMAP_CSRC)/libzbitmap.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

$(BUILD)/crushlzfse_sweep: $(HARNESS_ROOT)/tools/crushlzfse_sweep.c \
                    $(CODEC_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

$(BUILD)/crushlzvn_sweep: $(HARNESS_ROOT)/tools/crushlzvn_sweep.c \
                    $(CODEC_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

$(BUILD)/crushlz4_sweep: $(HARNESS_ROOT)/tools/crushlz4_sweep.c \
                    $(CODEC_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)

$(BUILD)/level_table: $(HARNESS_ROOT)/tools/level_table.c \
                    $(CODEC_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LIBS) $(APPLE_LIBS)


# Binaries only; fixtures survive.
clean:
	rm -rf $(BUILD)/bench $(BUILD)/asan $(BUILD)/tsan $(BUILD)/msan $(BUILD)/coverage \
	       $(BUILD)/make_fixtures $(BUILD)/make_fixtures_asan $(BUILD)/make_fixtures_san $(BUILD)/.logs* \
	       $(BUILD)/*.o $(BUILD)/*.dSYM $(CONFORMANCE_BINS) $(PROBE_BINS)

# Everything, fixtures included.
distclean:
	rm -rf $(BUILD)
