#!/bin/bash
set -x 
BASEDIR=$(pwd)
echo $BASEDIR
S2N_BASE="$BASEDIR/../../../.."
echo $S2N_BASE

cd $BASEDIR
cp $S2N_BASE/crypto/s2n_hmac.c crypto/
cp $S2N_BASE/crypto/s2n_hmac.h crypto
patch -p5 <hmac.patch

cd $BASEDIR
rm -r api
mkdir api
cd api
cp $S2N_BASE/api/s2n.h .

exit 0

cd $BASEDIR
rm -r tls
mkdir tls
cd tls
cp $S2N_BASE/tls/s2n_config.c .
cp $S2N_BASE/tls/s2n_connection.c .
cp $S2N_BASE/tls/s2n_crypto.h .
cp $S2N_BASE/tls/s2n_prf.c .
cp $S2N_BASE/tls/s2n_record.h .
cp $S2N_BASE/tls/s2n_config.h .
cp $S2N_BASE/tls/s2n_connection.h .
cp $S2N_BASE/tls/s2n_handshake.h .
cp $S2N_BASE/tls/s2n_prf.h .
cp $S2N_BASE/tls/s2n_tls_parameters.h .




cd $BASEDIR
rm -r error
mkdir error
cd error
cp $S2N_BASE/error/s2n_errno.c .
cp $S2N_BASE/error/s2n_errno.h .


