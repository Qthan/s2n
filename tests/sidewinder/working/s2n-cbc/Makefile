include ../../lib/ct-verif.mk

cflags +=-D__TIMING_CONTRACTS__
cflags += -fPIC -std=c99 -fgnu89-inline
extras += crypto/s2n_hmac.c  crypto/s2n_hash.c crypto/s2n_fips.c utils/s2n_safety.c
goals  += simple_cbc_wrapper@cbc.c
full_self_comp += true
smtlog += p.smt2
shadowingArgs += "self_comp_mode=full,branchcond_assertion=assert_never,memory_assertion=assert_never"
timing += true
#printModel += true
