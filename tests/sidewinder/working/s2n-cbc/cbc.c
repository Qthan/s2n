/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <sys/param.h>
#include <stdint.h>

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "crypto/s2n_hmac.h"

//#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_connection.h"

#include <smack.h>
#include <smack-contracts.h>
#include "ct-verif.h"
#include "sidewinder.h"

const int MAX_SIZE = 1024;


int double_loop(int old_mismatches, struct s2n_blob *decrypted, int check, int cutoff, int padding_length) {
  __VERIFIER_assert(decrypted->size >= 0);
  __VERIFIER_assert(decrypted->size <= 1024);
  int mismatches = old_mismatches;
  for (int i = 0, j = decrypted->size - 1 - check; i < check && j < decrypted->size; i++, j++) {
    invariant(i <= check);
    invariant(j == i + decrypted->size - check - 1);
    uint8_t mask = ~(0xff << ((i >= cutoff) * 8));
    mismatches |= (decrypted->data[j] ^ padding_length) & mask;
  }
  return mismatches;
}


/* A TLS CBC record looks like ..
 *
 * [ Payload data ] [ HMAC ] [ Padding ] [ Padding length byte ]
 *
 * Each byte in the padding is expected to be set to the same value
 * as the padding length byte. So if the padding length byte is '2'
 * then the padding will be [ '2', '2' ] (there'll be three bytesb
 * set to that value if you include the padding length byte).
 *
 * The goal of s2n_verify_cbc() is to verify that the padding and hmac
 * are correct, without leaking (via timing) how much padding there
 * actually is: as this is considered secret. 
 *
 * In addition to our efforts here though, s2n also wraps any CBC
 * verification error (or record parsing error in general) with
 * a randomized delay of between 1ms and 10 seconds. See s2n_connection.c.
 * This amount of delay randomization is sufficient to increase the
 * complexity of attack for even a 1 microsecond timing leak (which
 * is quite large) by a factor of around 83 trillion.
 */

int s2n_verify_cbc2(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted)

/* int s2n_verify_cbc( */
/* 		   struct s2n_hmac_state * copy,  */
/* 		   //		   struct s2n_mode mode, */
/* 		   struct s2n_hmac_state *hmac, struct s2n_blob *decrypted) */
{
    /* Set up MAC copy workspace */
    /* struct s2n_hmac_state *copy = &conn->client->record_mac_copy_workspace; */
    /* if (conn->mode == S2N_CLIENT) { */
    /*    copy = &conn->server->record_mac_copy_workspace; */
    /* } */

    struct s2n_hmac_state *copy = &conn->client->record_mac_copy_workspace;

  
    uint8_t mac_digest_size = 20;
    //GUARD(s2n_hmac_digest_size(hmac->alg, &mac_digest_size));

    /* The record has to be at least big enough to contain the MAC,
     * plus the padding length byte */
    //gt_check(decrypted->size, mac_digest_size);
    __VERIFIER_assume(decrypted->size > mac_digest_size);

    __VERIFIER_assert(mac_digest_size == 20);

    int payload_and_padding_size = decrypted->size - mac_digest_size;

    __VERIFIER_assert(payload_and_padding_size <= MAX_SIZE - 20);
    /* Determine what the padding length is */
    uint8_t padding_length = decrypted->data[decrypted->size - 1];
    __VERIFIER_assume(padding_length >= 0);
    __VERIFIER_assume(padding_length <  256);
    
    int payload_length = MAX(payload_and_padding_size - padding_length - 1, 0);
    __VERIFIER_assume(payload_length > 0);

    __VERIFIER_assert(hmac->currently_in_hash_block >= 0);

    /* Update the MAC */
    GUARD(s2n_hmac_update(hmac, decrypted->data, payload_length));
    GUARD(s2n_hmac_copy(copy, hmac));
    //Compute a MAC on the rest of the data so that we perform the same number of hash operations

    /* Check the MAC */
    uint8_t check_digest[S2N_MAX_DIGEST_LEN];
    //__VERIFIER_assert(mac_digest_size <= sizeof(check_digest));
    //lte_check(mac_digest_size, sizeof(check_digest));
    GUARD(s2n_hmac_digest_two_compression_rounds(hmac, check_digest, mac_digest_size));
    GUARD(s2n_hmac_update(copy, decrypted->data + payload_length + mac_digest_size, decrypted->size - payload_length - mac_digest_size - 1));
    
    int mismatches = s2n_constant_time_equals(decrypted->data + payload_length, check_digest, mac_digest_size) ^ 1;

    /* SSLv3 doesn't specify what the padding should actually be */
    /* if (conn->actual_protocol_version == S2N_SSLv3) { */
    /*     return 0 - mismatches; */
    /* } */

    /* Check the maximum amount that could theoretically be padding */
    // LEAVE Out int check = MIN(255, (payload_and_padding_size - 1));


    int check = payload_and_padding_size - 1;

    int cutoff = check - padding_length;
    /* for (int i = 0, j = decrypted->size - 1 - check; i < check && j < decrypted->size; i++, j++) { */
    /*   invariant(i <= check); */
    /*   invariant(j == i + decrypted->size - check - 1); */
    /*   uint8_t mask = ~(0xff << ((i >= cutoff) * 8)); */
    /*   mismatches |= (decrypted->data[j] ^ padding_length) & mask; */
    /* } */

    int mis = double_loop(mismatches, decrypted, check, cutoff, padding_length);
    /* GUARD(s2n_hmac_reset(copy)); */

     if (mis) {
      S2N_ERROR(S2N_ERR_CBC_VERIFY);
    }

    return 0;
}

int simple_cbc_wrapper(int currently_in_hash_block, int mlocked, int size, int *xor_pad, int * digest_pad)
{

  __VERIFIER_ASSERT_MAX_LEAKAGE(68);

  public_in(__SMACK_value(currently_in_hash_block));
  __VERIFIER_assume(currently_in_hash_block >= 0);
  __VERIFIER_assume(currently_in_hash_block < BLOCK_SIZE);

  public_in(__SMACK_value(mlocked));

  struct s2n_hmac_state hmac = {
    .alg = S2N_HMAC_SHA1,
    .hash_block_size = BLOCK_SIZE,
    .currently_in_hash_block = 0,
    .digest_size = SHA_DIGEST_LENGTH,
    .xor_pad_size = BLOCK_SIZE,
    .inner.alg = S2N_HASH_SHA1,
    .inner.currently_in_hash_block = 0,
    .inner_just_key.alg = S2N_HASH_SHA1,
    .inner_just_key.currently_in_hash_block = 0,
    .outer.alg = S2N_HASH_SHA1,
    .outer.currently_in_hash_block = 0,
    .outer_just_key.alg = S2N_HASH_SHA1,
    .outer_just_key.currently_in_hash_block = 0,
     .xor_pad = *xor_pad,
    //xor_pad is an array
    .digest_pad = *digest_pad
  };


  struct s2n_crypto_parameters client;
  struct s2n_connection conn = {
    .client = &client
  };
  
  //struct s2n_hmac_state hmac_copy;

  int data[MAX_SIZE];
  public_in(__SMACK_value(size));
  __VERIFIER_assume(size >= 0);
  __VERIFIER_assume(size <= MAX_SIZE);

  struct s2n_blob decrypted = {
    .data = data,
    .size = size,
    .allocated = 1,
    .mlocked = mlocked
  };

  return s2n_verify_cbc2(&conn, &hmac, &decrypted);
}
