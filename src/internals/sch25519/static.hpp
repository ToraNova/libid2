/*
 * SCH25519 - id2 library
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Chia Jason
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * SCH25519 signature scheme key structure
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#ifndef _SCH25519_STATIC_HPP_
#define _SCH25519_STATIC_HPP_

// Size definitions TODO: please edit NEPC and NSCC accordingly
// for Curve25519 keys
// -- NEPC - base/point components
// -- NSSC - scalar components
#define PKEY_NEPC 3
#define PKEY_NSCC 0
#define PKEY_SZ PKEY_NEPC*RS_EPSZ+PKEY_NSCC*RS_SCSZ
// only define secrets here, ignore the pubkey element in skey
#define SKEY_NEPC 0
#define SKEY_NSCC 1
#define SKEY_SZ PKEY_NEPC*RS_EPSZ+PKEY_NSCC*RS_SCSZ+ \
		SKEY_NEPC*RS_EPSZ+SKEY_NSCC*RS_SCSZ
#define SKEY_NC SKEY_NEPC+SKEY_NSCC+PKEY_NEPC+PKEY_NSCC
// signature
#define SGNT_NEPC 3
#define SGNT_NSCC 2
#define SGNT_SZ SGNT_NEPC*RS_EPSZ+SGNT_NSCC*RS_SCSZ

#include <stddef.h>

namespace SCH25519 {

	//TODO: change the key structures
	struct pubkey{
		unsigned char *B;
		unsigned char *P1;
		unsigned char *P2;
	};

	struct seckey{
		unsigned char *a;
		struct pubkey *pub;
	};

	struct signat{
		//scalars
		unsigned char *s;
		unsigned char *x;
		//points
		unsigned char *U;
		unsigned char *V;
		unsigned char *B;
	};

	//randomly generate a key
	//return a key on success, null on error
	struct seckey *randomkey();

	//generate a signature based on a seckey and message
	//key - secret key used to sign message
	//mbuffer - buffer containing message to be signed
	//mlen - length of contents in mbuffer
	struct signat *signatgen(
		struct seckey *key,
		unsigned char *mbuffer, size_t mlen
	);

	//check a signature
	int signatchk(
		struct pubkey *par,
		struct signat *sig,
		unsigned char *mbuffer, size_t mlen
	);

	// hash( m, u, v) to a scalar in ristretto255
	// output is always size RS_SCSZ
	unsigned char *hashexec(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *ubuffer,
		unsigned char *vbuffer
	);
	//frees up the hash
	void hashfree(unsigned char *hash);

	//serialize the secret,public and signature from a structure
	size_t secserial(struct seckey *in, unsigned char **sbuffer, size_t *slen);
	size_t pubserial(struct seckey *in, unsigned char **pbuffer, size_t *plen);
	size_t sigserial(struct signat *in, unsigned char **obuffer, size_t *olen);

	//creates a public key struct from the serialize string
	//inverse of secserial, pubserial and sigserial
	struct seckey *secstruct(unsigned char *sbuffer, size_t slen);
	struct pubkey *pubstruct(unsigned char *pbuffer, size_t plen);
	struct signat *sigstruct(unsigned char *obuffer, size_t olen);

	//destroy secret,public and signature struct
	void secdestroy(struct seckey *in);
	void pubdestroy(struct pubkey *in);
	void sigdestroy(struct signat *in);

	//print out key,signature structure (debugging use)
	void secprint(struct seckey *in);
	void pubprint(struct pubkey *in);
	void sigprint(struct signat *in);
}

#endif
