/*
 * Shadow <arm_neon.h> for CBMC: put harness/proofs/simd/include first on
 * the include path. The intrinsics the decoders use (check_intrinsics.py)
 * map to the models in neon_model.h. Every other intrinsic the translation
 * unit mentions is declared without a body, only so encoder code still
 * type-checks; a proof that reaches one fails on the missing body.
 */
#ifndef CRUSH_SHADOW_ARM_NEON_H
#define CRUSH_SHADOW_ARM_NEON_H
#define CRUSH_SIMD_SHADOW_NEON 1

#include <stdint.h>
#include "../neon_model.h"

typedef M_uint8x8_t uint8x8_t;
typedef M_uint8x16_t uint8x16_t;

#define vld1_u8 M_vld1_u8
#define vld1q_u8 M_vld1q_u8
#define vst1_u8 M_vst1_u8
#define vst1q_u8 M_vst1q_u8
#define vcombine_u8 M_vcombine_u8
#define vqtbl1_u8 M_vqtbl1_u8

/* Unmodelled: types and declarations only. */
typedef struct { int8_t v[8]; } int8x8_t;
typedef struct { int8_t v[16]; } int8x16_t;
typedef struct { int16_t v[4]; } int16x4_t;
typedef struct { int16_t v[8]; } int16x8_t;
typedef struct { int32_t v[4]; } int32x4_t;
typedef struct { uint16_t v[4]; } uint16x4_t;
typedef struct { uint16_t v[8]; } uint16x8_t;
typedef struct { uint32_t v[2]; } uint32x2_t;
typedef struct { uint32_t v[4]; } uint32x4_t;
typedef struct { uint64_t v[1]; } uint64x1_t;
typedef struct { uint64_t v[2]; } uint64x2_t;
typedef struct { uint8x16_t val[2]; } uint8x16x2_t;

int32x4_t vaddq_s32(int32x4_t, int32x4_t);
uint32x4_t vaddq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vaddq_u8(uint8x16_t, uint8x16_t);
uint8_t vaddv_u8(uint8x8_t);
uint16_t vaddvq_u16(uint16x8_t);
uint8x8_t vand_u8(uint8x8_t, uint8x8_t);
uint16x8_t vandq_u16(uint16x8_t, uint16x8_t);
uint32x4_t vandq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vandq_u8(uint8x16_t, uint8x16_t);
uint8x8_t vbic_u8(uint8x8_t, uint8x8_t);
uint32x4_t vbicq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vbicq_u8(uint8x16_t, uint8x16_t);
uint16x8_t vbslq_u16(uint16x8_t, uint16x8_t, uint16x8_t);
uint32x4_t vbslq_u32(uint32x4_t, uint32x4_t, uint32x4_t);
uint8x8_t vceq_u8(uint8x8_t, uint8x8_t);
uint16x8_t vceqq_u16(uint16x8_t, uint16x8_t);
uint8x16_t vceqq_u8(uint8x16_t, uint8x16_t);
uint32x4_t vcgtq_u32(uint32x4_t, uint32x4_t);
uint32x4_t vcleq_u32(uint32x4_t, uint32x4_t);
uint8x8_t vclt_u8(uint8x8_t, uint8x8_t);
uint16x8_t vcltq_u16(uint16x8_t, uint16x8_t);
uint8x8_t vcnt_u8(uint8x8_t);
uint8x16_t vcntq_u8(uint8x16_t);
uint64x2_t vcombine_u64(uint64x1_t, uint64x1_t);
uint16x4_t vcreate_u16(uint64_t);
uint64x1_t vcreate_u64(uint64_t);
uint8x8_t vcreate_u8(uint64_t);
uint8x8_t vdup_n_u8(uint8_t);
int32x4_t vdupq_n_s32(int32_t);
uint16x8_t vdupq_n_u16(uint16_t);
uint32x4_t vdupq_n_u32(uint32_t);
uint64x2_t vdupq_n_u64(uint64_t);
uint8x16_t vdupq_n_u8(uint8_t);
uint8x16_t vdupq_laneq_u8(uint8x16_t, int);
uint8x16_t vextq_u8(uint8x16_t, uint8x16_t, int);
int16x4_t vget_high_s16(int16x8_t);
int8x8_t vget_high_s8(int8x16_t);
uint8x8_t vget_high_u8(uint8x16_t);
uint64_t vget_lane_u64(uint64x1_t, int);
int16x4_t vget_low_s16(int16x8_t);
int8x8_t vget_low_s8(int8x16_t);
uint8x8_t vget_low_u8(uint8x16_t);
uint32_t vgetq_lane_u32(uint32x4_t, int);
uint64_t vgetq_lane_u64(uint64x2_t, int);
uint64x1_t vld1_u64(const uint64_t *);
uint32x4_t vld1q_lane_u32(const uint32_t *, uint32x4_t, int);
uint16x8_t vld1q_u16(const uint16_t *);
uint32x4_t vld1q_u32(const uint32_t *);
uint8x16x2_t vld2q_u8(const uint8_t *);
uint16_t vmaxvq_u16(uint16x8_t);
uint16x8_t vminq_u16(uint16x8_t, uint16x8_t);
uint32x4_t vminq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vminq_u8(uint8x16_t, uint8x16_t);
uint16_t vminvq_u16(uint16x8_t);
uint32_t vminvq_u32(uint32x4_t);
uint8_t vminvq_u8(uint8x16_t);
int32x4_t vmovl_s16(int16x4_t);
int16x8_t vmovl_s8(int8x8_t);
uint32x4_t vmovl_u16(uint16x4_t);
uint16x8_t vmovl_u8(uint8x8_t);
uint8x8_t vmovn_u16(uint16x8_t);
uint32x4_t vmulq_u32(uint32x4_t, uint32x4_t);
uint16x8_t vorrq_u16(uint16x8_t, uint16x8_t);
uint32x4_t vorrq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vorrq_u8(uint8x16_t, uint8x16_t);
uint16x8_t vpadalq_u8(uint16x8_t, uint8x16_t);
uint8x16_t vpaddq_u8(uint8x16_t, uint8x16_t);
uint8x16_t vqtbl1q_u8(uint8x16_t, uint8x16_t);
uint16x4_t vreinterpret_u16_u8(uint8x8_t);
uint64x1_t vreinterpret_u64_u8(uint8x8_t);
int8x16_t vreinterpretq_s8_u8(uint8x16_t);
uint16x8_t vreinterpretq_u16_u8(uint8x16_t);
uint32x4_t vreinterpretq_u32_s32(int32x4_t);
uint32x4_t vreinterpretq_u32_u64(uint64x2_t);
uint32x4_t vreinterpretq_u32_u8(uint8x16_t);
uint64x2_t vreinterpretq_u64_u32(uint32x4_t);
uint64x2_t vreinterpretq_u64_u8(uint8x16_t);
uint8x16_t vreinterpretq_u8_u64(uint64x2_t);
uint16x8_t vshlq_n_u16(uint16x8_t, int);
uint32x4_t vshlq_n_u32(uint32x4_t, int);
uint8x16_t vshlq_n_u8(uint8x16_t, int);
uint32x4_t vshlq_u32(uint32x4_t, int32x4_t);
uint16x8_t vshrq_n_u16(uint16x8_t, int);
uint32x4_t vshrq_n_u32(uint32x4_t, int);
void vst1q_u32(uint32_t *, uint32x4_t);
uint16x8_t vsubq_u16(uint16x8_t, uint16x8_t);
uint32x4_t vsubq_u32(uint32x4_t, uint32x4_t);
uint8x16_t vsubq_u8(uint8x16_t, uint8x16_t);
uint8x8_t vtbl1_u8(uint8x8_t, uint8x8_t);
uint8x8_t vtst_u8(uint8x8_t, uint8x8_t);
uint32x4_t vuzp1q_u32(uint32x4_t, uint32x4_t);
uint32x4_t vuzp2q_u32(uint32x4_t, uint32x4_t);
uint8x8_t vzip1_u8(uint8x8_t, uint8x8_t);
uint32x4_t vzip1q_u32(uint32x4_t, uint32x4_t);
uint64x2_t vzip1q_u64(uint64x2_t, uint64x2_t);
uint32x4_t vzip2q_u32(uint32x4_t, uint32x4_t);
uint64x2_t vzip2q_u64(uint64x2_t, uint64x2_t);

#endif
