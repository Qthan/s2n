#include <stdint.h>
#include <stdlib.h>
#include <smack.h>
#include "ct-verif.h"
void __VERIFIER_ASSERT_MAX_LEAKAGE(int max);
void __VERIFIER_ASSUME_LEAKAGE(int assumedLeakage);
void __VERIFIER_ASSERT_MAX_FOO(int max);

#define GUARD( x )      if ( (x) < 0 ) return -1

int test(int size) {
  int a = size % 64;
  int b = size & 0x3F;
  __VERIFIER_assert(a == b);
  return 0;
}
