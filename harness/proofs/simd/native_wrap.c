/*
 * Wraps an existing proof harness (NATIVE_TARGET, e.g. "../zbm_copy_fwd.c")
 * for a native-SIMD build: compiling this file fails unless crush_simd.h
 * took the native branch for NATIVE_ISA, through the shadow intrinsic
 * headers rather than the compiler's, on an LP64 little-endian model with
 * the shipping char signedness.
 */
#include NATIVE_TARGET

#if defined(CRUSH_SIMD_PORTABLE)
#error "crush_simd.h took the portable branch"
#endif

#if NATIVE_ISA == 1  /* arm64 NEON */
#  if !defined(__ARM_NEON) || !defined(__aarch64__) || defined(__x86_64__)
#    error "not an arm64 NEON configuration"
#  endif
#  if !defined(CRUSH_SIMD_SHADOW_NEON) || !defined(CRUSH_NEON_MODEL_H)
#    error "shadow arm_neon.h was not used"
#  endif
#  if defined(_AARCH64_NEON_H_) || defined(__ARM_NEON_H)
#    error "the compiler's arm_neon.h was included"
#  endif
#elif NATIVE_ISA == 2  /* x86-64-v3 */
#  if defined(__ARM_NEON) || defined(__aarch64__) || !defined(__x86_64__) || \
      !defined(__SSE4_1__) || !defined(__POPCNT__) || !defined(__AVX2__)
#    error "not an x86-64-v3 configuration"
#  endif
#  if !defined(CRUSH_SIMD_SHADOW_X86) || !defined(CRUSH_SSE_MODEL_H)
#    error "shadow x86 intrinsic headers were not used"
#  endif
#  if defined(_EMMINTRIN_H_INCLUDED) || defined(_SMMINTRIN_H_INCLUDED) || \
      defined(_TMMINTRIN_H_INCLUDED) || defined(_IMMINTRIN_H_INCLUDED) || \
      defined(__EMMINTRIN_H) || defined(__SMMINTRIN_H)
#    error "a compiler x86 intrinsic header was included"
#  endif
#else
#  error "NATIVE_ISA must be 1 (arm64) or 2 (x86-64-v3)"
#endif

_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8 && sizeof(size_t) == 8,
               "LP64");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little-endian");
/* Apple arm64 and x86-64 both have a signed char. */
_Static_assert((char)-1 < 0, "signed char");
