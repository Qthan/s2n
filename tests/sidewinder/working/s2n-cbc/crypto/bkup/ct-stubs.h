#pragma once

#include "s2n_hash.h"
struct _stub_s2n_hash_state {
  int currently_in_hash_block;
};

//SHA1
enum {
  PER_BLOCK_COST = 1000,
  PER_BYTE_COST = 0,
  BLOCK_SIZE = 64,          
  LENGTH_FIELD_SIZE = 8     
};

enum {
  SUCCESS = 0,
  FAILURE = -1
};

/* extern int _stub_s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out) __attribute__((used)); */
extern int _stub_s2n_hash_new(struct s2n_hash_state *state) __attribute__((used));
extern int _stub_s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg) __attribute__((used));
extern int _stub_s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size) __attribute__((used));
extern int _stub_s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size) __attribute__((used));
extern int _stub_s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from) __attribute__((used));
extern int _stub_s2n_hash_reset(struct s2n_hash_state *state) __attribute__((used));
extern int _stub_s2n_hash_free(struct s2n_hash_state *state) __attribute__((used));


extern void __VERIFIER_TIMING_CONTRACT(void *contract);
