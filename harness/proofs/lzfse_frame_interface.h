/*
 * Callee contracts the LZFSE frame proof (lzfse_decode_frame) consumes,
 * under the shipping table sizes (LZFSE_EXACT_FSE). Built with
 * -DLZFSE_PROOF_FRAME_INTERFACE, which hides the legacy reduced-config
 * declarations in lzfse_internal.h. Include after lzfse_internal.h and
 * before lzfse_decode_base.c.
 *
 * Table validity is the ghost lzfse_proof_tables_ok (lzfse_internal.h).
 * Each clause states what the frame needs; the evidence for it is:
 *   fse_init_decoder_table        footprint: fse_init_decoder_table target;
 *                                 rows: fse_literal_table_valid (zero seed)
 *                                 and fse_literal_table_preserve (valid
 *                                 seed), an arbitrary row valid after
 *                                 success when it was valid before.
 *   fse_init_value_decoder_table  footprint: fse_init_value_decoder_table;
 *                                 rows: fse_{l,m,d}_table_coverage and
 *                                 fse_{l,m,d}_table_preserve, likewise.
 *   lzfse_decode_literals         frama/lzfse_literals_native.py proves the
 *                                 shipping loop; frama/lzfse_contract_bridge.py
 *                                 and frama/lzfse_frame_step_bridge.py align
 *                                 its contracts with this interface.
 *   lzfse_decode_lmd              frama/lzfse_lmd_native.py proves the
 *                                 shipping loop and DST_FULL resume clause;
 *                                 the same two bridges align its contracts
 *                                 with this interface.
 */
#ifndef LZFSE_FRAME_INTERFACE_H
#define LZFSE_FRAME_INTERFACE_H

#if !defined(LZFSE_PROOF_FRAME_INTERFACE)
#error "build with -DLZFSE_PROOF_FRAME_INTERFACE"
#endif

//  The builders keep every table row valid on success, given valid rows
//  before (lzfse_proof_tables_ok, see lzfse_internal.h). Their row values
//  are abstracted into the ghost, but their real table writes stay in the
//  write frame.
#define LZFSE_PROOF_BUILDER_TABLE_CONTRACT                                    \
  __CPROVER_requires(lzfse_proof_tables_ok == 1)                            \
  __CPROVER_assigns(lzfse_proof_tables_ok,                                   \
                    __CPROVER_object_upto(t,                                 \
                      (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t)) \
  __CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1) \
  __CPROVER_ensures(lzfse_proof_tables_ok == (__CPROVER_return_value == 0))

int fse_init_decoder_table(int nstates, int nsymbols,
                           const uint16_t *__restrict freq,
                           int32_t *__restrict t)
__CPROVER_requires(nstates == LZFSE_ENCODE_LITERAL_STATES &&
                   nsymbols == LZFSE_ENCODE_LITERAL_SYMBOLS)
__CPROVER_requires(__CPROVER_r_ok(freq, (size_t)nsymbols * sizeof *freq))
__CPROVER_requires(__CPROVER_w_ok(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
__CPROVER_requires(!__CPROVER_same_object(freq, t))
LZFSE_PROOF_BUILDER_TABLE_CONTRACT;

int fse_init_value_decoder_table(int nstates, int nsymbols,
                                 const uint16_t *__restrict freq,
                                 const uint8_t *__restrict symbol_vbits,
                                 const int32_t *__restrict symbol_vbase,
                                 fse_value_decoder_entry *__restrict t)
__CPROVER_requires((nstates == LZFSE_ENCODE_L_STATES && nsymbols == LZFSE_ENCODE_L_SYMBOLS &&
                    symbol_vbits == l_extra_bits && symbol_vbase == l_base_value) ||
                   (nstates == LZFSE_ENCODE_M_STATES && nsymbols == LZFSE_ENCODE_M_SYMBOLS &&
                    symbol_vbits == m_extra_bits && symbol_vbase == m_base_value) ||
                   (nstates == LZFSE_ENCODE_D_STATES && nsymbols == LZFSE_ENCODE_D_SYMBOLS &&
                    symbol_vbits == d_extra_bits && symbol_vbase == d_base_value))
__CPROVER_requires(__CPROVER_r_ok(freq, (size_t)nsymbols * sizeof *freq))
__CPROVER_requires(__CPROVER_w_ok(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
__CPROVER_requires(!__CPROVER_same_object(freq, t))
LZFSE_PROOF_BUILDER_TABLE_CONTRACT;

//  The x86 dispatch proof adds the dispatcher's CPUID memo.
#ifndef LZFSE_PROOF_HOT_EXTRA_ASSIGNS
#define LZFSE_PROOF_HOT_EXTRA_ASSIGNS
#endif

//  Contracts the frame needs from the two hot loops; the BMI2 dispatch proof
//  (lzfse_dispatch_*) reuses them for both clones.
#define LZFSE_PROOF_LITERALS_CONTRACT \
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))                                       \
__CPROVER_requires(__CPROVER_r_ok(header1, sizeof *header1))                            \
__CPROVER_requires(bs == &s->compressed_lzfse_block_state)                              \
__CPROVER_requires(!__CPROVER_same_object(header1, s))                                  \
__CPROVER_requires(!__CPROVER_same_object(header1, s->src_begin))                        \
__CPROVER_requires(LZFSE_PROOF_DECODER_BUFFERS(s))                                      \
__CPROVER_requires(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src_begin) <= PTRDIFF_MAX) \
__CPROVER_requires(LZFSE_OFFSET(s->src) - LZFSE_OFFSET(s->src_begin) >= 16)             \
__CPROVER_requires(header1->n_literal_payload_bytes <=                                  \
                   (size_t)(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src)))           \
__CPROVER_requires(header1->n_literals <= LZFSE_LITERALS_PER_BLOCK)                     \
__CPROVER_requires(header1->literal_bits >= -7 && header1->literal_bits <= 0)           \
__CPROVER_requires(header1->literal_state[0] < LZFSE_ENCODE_LITERAL_STATES &&           \
                   header1->literal_state[1] < LZFSE_ENCODE_LITERAL_STATES &&           \
                   header1->literal_state[2] < LZFSE_ENCODE_LITERAL_STATES &&           \
                   header1->literal_state[3] < LZFSE_ENCODE_LITERAL_STATES)             \
__CPROVER_requires(lzfse_proof_tables_ok == 1)                              \
__CPROVER_assigns(s->src, bs->current_literal,                                          \
                  __CPROVER_object_upto(bs->literals, sizeof bs->literals))             \
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)          \
__CPROVER_ensures(s->src == __CPROVER_old(s->src) + header1->n_literal_payload_bytes)   \
__CPROVER_ensures(__CPROVER_return_value == 0 ==> bs->current_literal == bs->literals) \
LZFSE_PROOF_HOT_EXTRA_ASSIGNS

#define LZFSE_PROOF_LMD_CONTRACT \
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))                                                                        \
__CPROVER_requires(LZFSE_PROOF_DECODER_BUFFERS(s))                                                                       \
__CPROVER_requires(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src_begin) <= PTRDIFF_MAX)                                 \
__CPROVER_requires(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin) <= PTRDIFF_MAX)                                 \
__CPROVER_requires(LZFSE_PROOF_LMD_START(s))                                                                             \
__CPROVER_requires(lzfse_proof_tables_ok == 1)                                  \
__CPROVER_assigns(s->dst,                                                                                                \
                  __CPROVER_object_upto(s->dst_begin, (size_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin))),  \
                  s->compressed_lzfse_block_state.l_value,                                                               \
                  s->compressed_lzfse_block_state.m_value,                                                               \
                  s->compressed_lzfse_block_state.d_value,                                                               \
                  s->compressed_lzfse_block_state.l_state,                                                               \
                  s->compressed_lzfse_block_state.m_state,                                                               \
                  s->compressed_lzfse_block_state.d_state,                                                               \
                  s->compressed_lzfse_block_state.lmd_in_stream,                                                         \
                  s->compressed_lzfse_block_state.n_matches,                                                             \
                  s->compressed_lzfse_block_state.lmd_in_buf,                                                            \
                  s->compressed_lzfse_block_state.current_literal)                                                       \
__CPROVER_ensures(__CPROVER_return_value == LZFSE_STATUS_OK ||                                                           \
                  __CPROVER_return_value == LZFSE_STATUS_DST_FULL ||                                                     \
                  __CPROVER_return_value == LZFSE_STATUS_ERROR)                                                          \
__CPROVER_ensures(__CPROVER_same_object(s->dst, s->dst_begin))                                                           \
__CPROVER_ensures(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(__CPROVER_old(s->dst)))                                           \
__CPROVER_ensures(LZFSE_OFFSET(s->dst) <= LZFSE_OFFSET(s->dst_end))                                                      \
__CPROVER_ensures(__CPROVER_return_value == LZFSE_STATUS_DST_FULL ==>                                                    \
                  LZFSE_PROOF_LMD_START(s)) \
LZFSE_PROOF_HOT_EXTRA_ASSIGNS

int lzfse_decode_literals(lzfse_decoder_state *s,
                          const lzfse_compressed_block_header_v1 *header1,
                          lzfse_compressed_block_decoder_state *bs)
LZFSE_PROOF_LITERALS_CONTRACT;

int lzfse_decode_lmd(lzfse_decoder_state *s)
LZFSE_PROOF_LMD_CONTRACT;

#endif
