#!/bin/bash
set -x 
BASEDIR=$(pwd)
echo $BASEDIR
S2N_BASE="$BASEDIR/../../../.."
echo $S2N_BASE

cd $BASEDIR
mkdir -p crypto
#The hmac should be based off the old hmac, so just apply the patches to add the invarients
cp $S2N_BASE/crypto/s2n_hmac.c crypto/
cp $S2N_BASE/crypto/s2n_hmac.h crypto/
patch -p5 <hmac.patch

#the hash uses my stubs for now, so replace the file
cp old_proof/s2n_hash.c crypto/
cp old_proof/s2n_hash.h crypto/

mkdir -p tls
#add invariants etc needed for the proof to the s2n_cbc code
cp $S2N_BASE/tls/s2n_cbc.c tls/
patch -p5 < cbc.patch

mkdir -p utils
cp old_proof/s2n_safety.c utils/
cp old_proof/s2n_safety.h utils/

