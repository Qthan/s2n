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

#pragma once

//#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#include "error/s2n_errno.h"
#include "s2n_annotations.h"
#include "sidewinder.h"

void __VERIFIER_assume(int);

/* NULL check a pointer */
#define notnull_check( ptr )           do { if ( (ptr) == NULL ) { S2N_ERROR(S2N_ERR_NULL); } } while(0)
#define MEMCOPY_COST 2

static inline void* trace_memcpy_check(void *restrict to, const void *restrict from, size_t size, const char *debug_str)
{
    __VERIFIER_ASSUME_LEAKAGE(size * MEMCOPY_COST);
    return memcpy(to, from, size);
}

/* Check memcpy and memset's arguments, if these are not right, log an error
 */
#define memcpy_check( d, s, n )                                             \
  do {                                                                      \
    memcpy(d,s,n);							\
  } while(0)

#define memset_check( d, c, n )						\
  do {                                                                      \
    __typeof( n ) __tmp_n = ( n );                                          \
    if ( __tmp_n ) {                                                        \
      __typeof( d ) __tmp_d = ( d );                                        \
      notnull_check( __tmp_d );                                             \
      my_memset( __tmp_d, (c), __tmp_n);                                    \
    }                                                                       \
  } while(0)

/* Range check a number */
#define gte_check(n, min)  __VERIFIER_assume( (n) >= (min) )
#define lte_check(n, max)  __VERIFIER_assume( (n) <= (max) )
#define gt_check(n, min)   __VERIFIER_assume( (n) >  (min) )
#define lt_check(n, max)   __VERIFIER_assume( (n) <  (max) )
#define eq_check(a, b)     __VERIFIER_assume( (a) ==  (b) )
#define ne_check(a, b)     __VERIFIER_assume( (a) !=  (b) )
#define inclusive_range_check( low, n, high )   \
  do  {                                         \
    __typeof( n ) __tmp_n = ( n );              \
    gte_check(__tmp_n, low);                    \
    lte_check(__tmp_n, high);                   \
  } while (0)
#define exclusive_range_check( low, n, high )   \
  do {                                          \
    __typeof( n ) __tmp_n = ( n );              \
    gt_check(__tmp_n, low);                     \
    lt_check(__tmp_n, high);                    \
  } while (0)

#define GUARD( x ) __VERIFIER_assume( (x) >= 0 )
#define GUARD_PTR( x )  if ( (x) < 0 ) return NULL

/**
 * Get the process id
 *
 * Returns:
 *  The process ID of the current process
 */
extern pid_t s2n_actual_getpid();

/* Returns 1 if a and b are equal, in constant time */
extern int s2n_constant_time_equals(const uint8_t * a, const uint8_t * b, uint32_t len);

/* Copy src to dst, or don't copy it, in constant time */
extern int s2n_constant_time_copy_or_dont(const uint8_t * dst, const uint8_t * src, uint32_t len, uint8_t dont);