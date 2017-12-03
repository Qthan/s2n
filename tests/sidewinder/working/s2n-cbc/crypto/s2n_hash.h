#pragma once

#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#define MAX_DIGEST_LENGTH SHA512_DIGEST_LENGTH

typedef enum {
    S2N_HASH_NONE,
    S2N_HASH_MD5,
    S2N_HASH_SHA1,
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
    S2N_HASH_MD5_SHA1
} s2n_hash_algorithm;

struct s2n_hash_state {
  s2n_hash_algorithm alg;
  int currently_in_hash_block;
};

//SHA1
enum {
  PER_BLOCK_COST = 1000,
  PER_BYTE_COST = 1,
  BLOCK_SIZE = 64,          
  LENGTH_FIELD_SIZE = 8     
};

enum {
  SUCCESS = 0,
  FAILURE = -1
};

extern int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out);
extern int s2n_hash_new(struct s2n_hash_state *state);
extern int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg);
extern int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size);
extern int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size);
extern int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from);
extern int s2n_hash_reset(struct s2n_hash_state *state);
extern int s2n_hash_free(struct s2n_hash_state *state);


