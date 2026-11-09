/*
 * Shadow <cpuid.h> for CBMC. The decoders call only __get_cpuid_count, to
 * pick the BMI2 LZFSE loops (lzfse_decode_base.c); the answer selects
 * between two token-identical function bodies (check_bmi2_clone.sh), so
 * the model is an arbitrary result. Like the real one, it leaves the
 * outputs untouched when it reports the leaf unsupported.
 */
#ifndef CRUSH_SHADOW_CPUID_H
#define CRUSH_SHADOW_CPUID_H
#define CRUSH_SIMD_SHADOW_CPUID 1

int nondet_crush_cpuid_ok(void);
unsigned nondet_crush_cpuid_reg(void);

static inline int __get_cpuid_count(unsigned leaf, unsigned subleaf,
                                    unsigned *eax, unsigned *ebx,
                                    unsigned *ecx, unsigned *edx)
{
    (void)leaf;
    (void)subleaf;
    if (!nondet_crush_cpuid_ok())
        return 0;
    *eax = nondet_crush_cpuid_reg();
    *ebx = nondet_crush_cpuid_reg();
    *ecx = nondet_crush_cpuid_reg();
    *edx = nondet_crush_cpuid_reg();
    return 1;
}

#endif
