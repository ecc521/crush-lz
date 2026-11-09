/*
 * Shadow x86 intrinsic headers for CBMC (emmintrin.h, tmmintrin.h,
 * smmintrin.h, nmmintrin.h and immintrin.h all include this). The
 * intrinsics the decoders use (check_intrinsics.py) map to the models in
 * sse_model.h. Every other intrinsic the translation unit mentions is
 * declared without a body, only so encoder code still type-checks; a proof
 * that reaches one fails on the missing body.
 */
#ifndef CRUSH_X86_SHADOW_H
#define CRUSH_X86_SHADOW_H
#define CRUSH_SIMD_SHADOW_X86 1

#include <stdint.h>
#include "../sse_model.h"

typedef M_m128i __m128i;
typedef M_m128i __m128i_u;

#define _mm_loadl_epi64(p) M_mm_loadl_epi64((const uint8_t *)(const void *)(p))
#define _mm_loadu_si128(p) M_mm_loadu_si128((const uint8_t *)(const void *)(p))
#define _mm_storel_epi64(p, v) M_mm_storel_epi64((uint8_t *)(void *)(p), (v))
#define _mm_storeu_si128(p, v) M_mm_storeu_si128((uint8_t *)(void *)(p), (v))
#define _mm_unpacklo_epi64 M_mm_unpacklo_epi64
#define _mm_shuffle_epi8 M_mm_shuffle_epi8

/* Unmodelled: types and declarations only. */
typedef struct { float f[4]; } __m128;
typedef struct { uint8_t b[32]; } __m256i;
typedef __m256i __m256i_u;

#define _MM_SHUFFLE(z, y, x, w) (((z) << 6) | ((y) << 4) | ((x) << 2) | (w))

__m256i _mm256_add_epi8(__m256i, __m256i);
__m256i _mm256_and_si256(__m256i, __m256i);
__m256i _mm256_broadcastsi128_si256(__m128i);
__m256i _mm256_castsi128_si256(__m128i);
__m128i _mm256_castsi256_si128(__m256i);
__m256i _mm256_cmpeq_epi8(__m256i, __m256i);
__m256i _mm256_cvtepu8_epi16(__m128i);
__m128i _mm256_extracti128_si256(__m256i, int);
__m256i _mm256_inserti128_si256(__m256i, __m128i, int);
__m256i _mm256_loadu_si256(const __m256i_u *);
__m256i _mm256_min_epu16(__m256i, __m256i);
__m256i _mm256_min_epu8(__m256i, __m256i);
int _mm256_movemask_epi8(__m256i);
__m256i _mm256_or_si256(__m256i, __m256i);
__m256i _mm256_set1_epi16(short);
__m256i _mm256_set1_epi8(char);
__m256i _mm256_setr_epi16(short, short, short, short, short, short, short, short,
                          short, short, short, short, short, short, short, short);
__m256i _mm256_setr_epi8(char, char, char, char, char, char, char, char,
                         char, char, char, char, char, char, char, char,
                         char, char, char, char, char, char, char, char,
                         char, char, char, char, char, char, char, char);
__m256i _mm256_slli_epi16(__m256i, int);
__m256i _mm256_sub_epi16(__m256i, __m256i);
__m256i _mm256_sub_epi8(__m256i, __m256i);
__m128i _mm_add_epi32(__m128i, __m128i);
__m128i _mm_add_epi64(__m128i, __m128i);
__m128i _mm_add_epi8(__m128i, __m128i);
__m128i _mm_alignr_epi8(__m128i, __m128i, int);
__m128i _mm_and_si128(__m128i, __m128i);
__m128i _mm_andnot_si128(__m128i, __m128i);
__m128i _mm_blendv_epi8(__m128i, __m128i, __m128i);
__m128i _mm_castps_si128(__m128);
__m128 _mm_castsi128_ps(__m128i);
__m128i _mm_cmpeq_epi16(__m128i, __m128i);
__m128i _mm_cmpeq_epi32(__m128i, __m128i);
__m128i _mm_cmpeq_epi8(__m128i, __m128i);
__m128i _mm_cmpgt_epi32(__m128i, __m128i);
__m128i _mm_cmplt_epi16(__m128i, __m128i);
__m128i _mm_cmplt_epi8(__m128i, __m128i);
__m128i _mm_cvtepu16_epi32(__m128i);
__m128i _mm_cvtepu8_epi16(__m128i);
int _mm_cvtsi128_si32(__m128i);
long long _mm_cvtsi128_si64(__m128i);
__m128i _mm_cvtsi32_si128(int);
__m128i _mm_cvtsi64_si128(long long);
int _mm_extract_epi32(__m128i, int);
__m128i _mm_insert_epi32(__m128i, int, int);
__m128i _mm_maddubs_epi16(__m128i, __m128i);
__m128i _mm_max_epu16(__m128i, __m128i);
__m128i _mm_min_epu16(__m128i, __m128i);
__m128i _mm_min_epu32(__m128i, __m128i);
__m128i _mm_min_epu8(__m128i, __m128i);
__m128i _mm_minpos_epu16(__m128i);
__m128i _mm_move_epi64(__m128i);
int _mm_movemask_epi8(__m128i);
__m128i _mm_mullo_epi32(__m128i, __m128i);
__m128i _mm_or_si128(__m128i, __m128i);
__m128i _mm_packus_epi16(__m128i, __m128i);
__m128i _mm_sad_epu8(__m128i, __m128i);
__m128i _mm_set1_epi16(short);
__m128i _mm_set1_epi32(int);
__m128i _mm_set1_epi64x(long long);
__m128i _mm_set1_epi8(char);
__m128i _mm_setr_epi16(short, short, short, short, short, short, short, short);
__m128i _mm_setr_epi32(int, int, int, int);
__m128i _mm_setr_epi8(char, char, char, char, char, char, char, char,
                      char, char, char, char, char, char, char, char);
__m128i _mm_setzero_si128(void);
__m128i _mm_shuffle_epi32(__m128i, int);
__m128 _mm_shuffle_ps(__m128, __m128, int);
__m128i _mm_slli_epi16(__m128i, int);
__m128i _mm_slli_epi32(__m128i, int);
__m128i _mm_slli_epi64(__m128i, int);
__m128i _mm_slli_si128(__m128i, int);
__m128i _mm_srl_epi32(__m128i, __m128i);
__m128i _mm_srli_epi16(__m128i, int);
__m128i _mm_srli_epi32(__m128i, int);
__m128i _mm_srli_si128(__m128i, int);
__m128i _mm_sub_epi16(__m128i, __m128i);
__m128i _mm_sub_epi32(__m128i, __m128i);
__m128i _mm_sub_epi8(__m128i, __m128i);
int _mm_testz_si128(__m128i, __m128i);
__m128i _mm_unpackhi_epi32(__m128i, __m128i);
__m128i _mm_unpackhi_epi64(__m128i, __m128i);
__m128i _mm_unpacklo_epi32(__m128i, __m128i);
__m128i _mm_unpacklo_epi8(__m128i, __m128i);
__m128i _mm_xor_si128(__m128i, __m128i);

#endif
