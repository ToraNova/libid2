/*
 * A Signature scheme implementation for TNC tight signatures
 * based of Finite-field arithmetic over Curve25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 * abbreviated as ts25519 - TNC signature using 25519
 *
*/

// declaration includes
#include "tsi25519.hpp"
#include "utils/debug.h"
#include "utils/bufhelp.h"

#include "internals/tnc.hpp"

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/randombytes.h>
//512bit hash (64byte)
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_verify_32.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>

using namespace std;

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * skey - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * pkey - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 * sig  - < 256 s >< 256 x >< 256 U >< 256 V >< 256 B > (does not need to store pkey anymore)
 *
 */
namespace ts25519
{
	//standard signatures
	int keygen(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//create a key structure
		struct tnc::seckey *key;
		//generate random key
		key = tnc::randomkey();
		if(key == NULL)return 1;

		//serialize the key to string
		tnc::secserial(key,sbuffer,slen);
		tnc::pubserial(key,pbuffer,plen);

#ifdef DEBUG
tnc::printsec(key);
printf("sbuffer %lu: ",*slen); ucbprint(*sbuffer, *slen); printf("\n");
printf("pbuffer %lu: ",*plen); ucbprint(*pbuffer, *plen); printf("\n");
#endif

		//clear the key
		secdestroy(key);

		return 0;
	}

	int sign(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		struct tnc::seckey *key;
		struct tnc::signat *sig;
		//obtain key from serialize string
		key = tnc::secstruct(sbuffer, slen);
		//signature generation
		sig = tnc::signatgen(key, mbuffer, mlen);

		//clear the secret key
		secdestroy(key);

		//serialize the signature to string
		tnc::sigserial(sig, obuffer, olen);

#ifdef DEBUG
printsig(sig);
printf("obuffer %lu: ",*olen); ucbprint(*obuffer, *olen); printf("\n");
#endif

		//clear the signature
		sigdestroy(sig);

		return 0;
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		//obtain paramter (public key) and signature from serialize string
		struct tnc::pubkey *par;
		struct tnc::signat *sig;
		par = tnc::pubstruct(pbuffer, plen);
		sig = tnc::sigstruct(obuffer, olen);

		rc = signatchk(par, sig, mbuffer, mlen);

		sigdestroy(sig);
		pubdestroy(par);
		return rc;
	}
}
