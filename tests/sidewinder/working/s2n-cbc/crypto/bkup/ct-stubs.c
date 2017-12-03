#include <stdint.h>
#include <stdlib.h>
#include <smack.h>
#include "ct-verif.h"
#include "ct-stubs.h"

void __VERIFIER_ASSERT_MAX_LEAKAGE(int max);
void __VERIFIER_ASSUME_LEAKAGE(int assumedLeakage);
void __VERIFIER_ASSERT_MAX_FOO(int max);

void __VERIFIER_TIMING_CONTRACT(void *contract);

/* int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out) */
/* { */
/*     switch (alg) { */
/*     case S2N_HASH_NONE:     *out = 0;                    break; */
/*     case S2N_HASH_MD5:      *out = MD5_DIGEST_LENGTH;    break; */
/*     case S2N_HASH_SHA1:     *out = SHA_DIGEST_LENGTH;    break; */
/*     case S2N_HASH_SHA224:   *out = SHA224_DIGEST_LENGTH; break; */
/*     case S2N_HASH_SHA256:   *out = SHA256_DIGEST_LENGTH; break; */
/*     case S2N_HASH_SHA384:   *out = SHA384_DIGEST_LENGTH; break; */
/*     case S2N_HASH_SHA512:   *out = SHA512_DIGEST_LENGTH; break; */
/*     case S2N_HASH_MD5_SHA1: *out = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH; break; */
/*     default: */
/*         S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM); */
/*     } */
/*     return 0; */
/* } */

int _stub_s2n_hash_new(struct s2n_hash_state *state)
{
  return SUCCESS;
}

int _stub_s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  state->alg = alg;
  state->currently_in_hash_block = 0;
  return SUCCESS;
}


int _stub_s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
  __VERIFIER_ASSUME_LEAKAGE(PER_BYTE_COST * size);
  state->currently_in_hash_block += size;
  int num_filled_blocks = state->currently_in_hash_block / BLOCK_SIZE;
  __VERIFIER_ASSUME_LEAKAGE(num_filled_blocks * PER_BLOCK_COST);
  state->currently_in_hash_block =  state->currently_in_hash_block % BLOCK_SIZE;
  return SUCCESS;
}

int _stub_s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  //All the leakage comes from the hash_update we do once we've updated the size fields
  assert(state->currently_in_hash_block < BLOCK_SIZE);

  // append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
  uint32_t bytes_to_add = 1;
  
  //https://github.com/B-Con/crypto-algorithms/blob/master/sha1.c#L114
  // append 0 â‰¤ k < 512 bits '0', such that the resulting message length in bits
  // is congruent to âˆ’64 â‰¡ 448 (mod 512)
  if(state->currently_in_hash_block < (BLOCK_SIZE - LENGTH_FIELD_SIZE)) {
    bytes_to_add += (BLOCK_SIZE - LENGTH_FIELD_SIZE) - state->currently_in_hash_block;
  } else {
    bytes_to_add += BLOCK_SIZE - state->currently_in_hash_block; // pad to fill the current block
    bytes_to_add += BLOCK_SIZE - LENGTH_FIELD_SIZE;  //pad the next block, leaving space for the length field
  }
  // append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
  bytes_to_add += LENGTH_FIELD_SIZE;
  //not actually adding the bytes, so don't worry about where they come from
  _stub_s2n_hash_update(state, NULL, bytes_to_add);
  return SUCCESS;
}

int _stub_s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  return SUCCESS;
}

int _stub_s2n_hash_reset(struct s2n_hash_state *state)
{
  __VERIFIER_ASSUME_LEAKAGE(0);
  return SUCCESS;
}

int _stub_s2n_hash_free(struct s2n_hash_state *state)
{
  return SUCCESS;
}
