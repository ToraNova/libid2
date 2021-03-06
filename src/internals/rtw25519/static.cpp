/*
 * internals/rtw25519/static.cpp - id2 library
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
 * Reset secure Twin Schnorr IBI
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include "static.hpp"

#include "../../utils/bufhelp.h"
#include "../../utils/debug.h"

//include general constant and macros
#include "../cmacro.h"

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium.h>

//#include <sodium/crypto_core_ristretto255.h>
//#include <sodium/crypto_scalarmult_ristretto255.h>
//#include <sodium/randombytes.h>
////512bit hash (64byte)
//#include <sodium/crypto_hash_sha512.h>
//#include <sodium/crypto_verify_32.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <cstring>

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * skey - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * pkey - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 * sig  - < 256 s >< 256 x >< 256 U >< 256 V >< 256 B > (does not need to store pkey anymore)
 *
 */

namespace rtw25519{

	void randomkey(void **out){
		//declare and allocate memory for key
		int rc; struct seckey *tmp;
		tmp = (struct seckey *)malloc( sizeof(struct seckey) );
		//allocate memory for pubkey
		tmp->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );
		unsigned char neg1[RS_SCSZ], neg2[RS_SCSZ], epv[RS_SCSZ];

		tmp->a1 = (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->a2 = (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->pub->B2 = (unsigned char *)malloc( RS_EPSZ );
		tmp->pub->P1 = (unsigned char *)malloc( RS_EPSZ );
		tmp->pub->P2 = (unsigned char *)malloc( RS_EPSZ );

		//sample a1,a2 and the base B
		// a1 -- x, a2 -- a
		crypto_core_ristretto255_scalar_random( tmp->a1 );
		crypto_core_ristretto255_scalar_random( tmp->a2 );
		crypto_core_ristretto255_scalar_random( epv );
		crypto_core_ristretto255_random( tmp->pub->B2 );

		crypto_core_ristretto255_scalar_negate(neg1 , tmp->a1);
		crypto_core_ristretto255_scalar_negate(neg2 , tmp->a2);

		debug("OK");
		rc = 0;
		// P1 = -a1B1 + (-a2)B2
		rc += crypto_scalarmult_ristretto255_base(tmp->pub->P1, neg1);
		rc += crypto_scalarmult_ristretto255(tmp->pub->P2, neg2, tmp->pub->B2);
		rc += crypto_core_ristretto255_add(
				tmp->pub->P1,
				tmp->pub->P1,
				tmp->pub->P2
				);
		rc += crypto_scalarmult_ristretto255_base(tmp->pub->P2, epv);
		if( rc != 0 ){ //abort if fail
			*out = NULL; return;
		}

		//recast and return
		*out = (void *) tmp; return;
	}

	void signatgen(
		void *vkey,
		const unsigned char *mbuffer, size_t mlen,
		void **out
	){
		//key recast
		int rc; struct signat *tmp;
		struct seckey *key = (struct seckey *)vkey;
		//declare and allocate for signature struct
		tmp = (struct signat *)malloc( sizeof( struct signat) );

		//--------------------------TODO START
		//nonce, r and hash
		unsigned char n1[RS_SCSZ];
		unsigned char n2[RS_SCSZ];

		//allocate for components
		tmp->s1= (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->s2= (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->U = (unsigned char *)malloc( RS_EPSZ );
		tmp->B2= (unsigned char *)malloc( RS_EPSZ );
		tmp->P2 = (unsigned char *)malloc( RS_EPSZ );

		//sample r (MUST RANDOMIZE, else secret key a will be exposed)
		crypto_core_ristretto255_scalar_random(n1);
		crypto_core_ristretto255_scalar_random(n2);

		rc = 0;
		//U = n1B2 + n2B2
		rc += crypto_scalarmult_ristretto255_base(tmp->U,n1);
		rc += crypto_scalarmult_ristretto255(tmp->B2,n2,key->pub->B2);
		rc += crypto_core_ristretto255_add( tmp->U, tmp->U, tmp->B2);
		if( rc != 0 ){ //abort if fail
			*out = NULL; return;
		}

		//store B2 and P2 on the signature
		memcpy( tmp->B2, key->pub->B2, RS_EPSZ );
		memcpy( tmp->P2, key->pub->P2, RS_EPSZ );

		tmp->x = hashexec(mbuffer, mlen, tmp->U, key->pub->P1);

		// s = r + xa
		crypto_core_ristretto255_scalar_mul( tmp->s1 , tmp->x, key->a1 );
		crypto_core_ristretto255_scalar_add( tmp->s1, tmp->s1, n1 );
		crypto_core_ristretto255_scalar_mul( tmp->s2 , tmp->x, key->a2 );
		crypto_core_ristretto255_scalar_add( tmp->s2, tmp->s2, n2 );
		//--------------------------TODO END

		*out = (void *) tmp; return;
	}

	int signatchk(
		void *vpar,
		void *vsig,
		const unsigned char *mbuffer, size_t mlen
	){
		// NOT IMPLEMENTED
		return 1;
	}

	unsigned char *hashexec(
		const unsigned char *mbuffer, size_t mlen,
		unsigned char *ubuffer,
		unsigned char *vbuffer
	){
		crypto_hash_sha512_state eh_state;
		unsigned char hshe[RS_HSSZ]; //hash
		unsigned char *out = (unsigned char *)malloc( RS_SCSZ );

		//compute hash
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, mbuffer, mlen);
		crypto_hash_sha512_update( &eh_state, ubuffer, RS_EPSZ);
		crypto_hash_sha512_update( &eh_state, vbuffer, RS_EPSZ);
		crypto_hash_sha512_final( &eh_state, hshe);
		crypto_core_ristretto255_scalar_reduce(
			out, (const unsigned char *)hshe
		);
		return out;
	}

	void hashfree(unsigned char *hash){
		sodium_memzero(hash, RS_SCSZ);
		free(hash); return;
	}

	size_t secserial(void *in, unsigned char **sbuffer, size_t *slen){
		size_t rs;
		struct seckey *ri = (struct seckey *)in; //recast the key
		//set size and allocate
		*slen = SKEY_SZ;
		*sbuffer = (unsigned char *)malloc( *(slen) );

		//a, B, P1, P2
		rs = copyskip( *sbuffer, ri->a1, 	0, 	RS_SCSZ);
		rs = copyskip( *sbuffer, ri->a2, 	rs, 	RS_SCSZ);
		rs = copyskip( *sbuffer, ri->pub->B2, 	rs, 	RS_EPSZ);
		rs = copyskip( *sbuffer, ri->pub->P1, 	rs, 	RS_EPSZ);
		rs = copyskip( *sbuffer, ri->pub->P2, 	rs, 	RS_EPSZ);

		return rs;
	}

	size_t pubserial(void *in, unsigned char **pbuffer, size_t *plen){
		size_t rs;
		struct seckey *ri = (struct seckey *)in; //recast the key
		//set size and allocate
		*plen = PKEY_SZ;
		*pbuffer = (unsigned char *)malloc( *(plen) );

		//B, P1, P2
		rs = copyskip( *pbuffer, ri->pub->B2, 	0, 	RS_EPSZ);
		rs = copyskip( *pbuffer, ri->pub->P1, 	rs, 	RS_EPSZ);
		rs = copyskip( *pbuffer, ri->pub->P2, 	rs, 	RS_EPSZ);

		return rs;
	}

	size_t sigserial(void *in, unsigned char **obuffer, size_t *olen){
		size_t rs;
		struct signat *ri = (struct signat *)in; //recast the key
		//set size and allocate
		*olen = SGNT_SZ;
		*obuffer = (unsigned char *)malloc( *(olen) );

		//s,x,U,V,B
		rs = copyskip( *obuffer, ri->s1, 	0, 	RS_SCSZ);
		rs = copyskip( *obuffer, ri->s2, 	rs, 	RS_SCSZ);
		rs = copyskip( *obuffer, ri->x, 	rs, 	RS_SCSZ);
		rs = copyskip( *obuffer, ri->U, 	rs, 	RS_EPSZ);
		rs = copyskip( *obuffer, ri->B2, 	rs, 	RS_EPSZ);
		rs = copyskip( *obuffer, ri->P2, 	rs, 	RS_EPSZ);

		return rs;
	}

	void secstruct(const unsigned char *sbuffer, size_t slen, void **out){
		struct seckey *tmp; size_t rs;
		//allocate memory for seckey
		tmp = (struct seckey *)malloc( sizeof(struct seckey));
		//allocate memory for pubkey
		tmp->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//allocate memory for the elements and scalars
		tmp->a1 = (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->a2 = (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->pub->B2 = (unsigned char *)malloc( RS_EPSZ );
		tmp->pub->P1 = (unsigned char *)malloc( RS_EPSZ );
		tmp->pub->P2 = (unsigned char *)malloc( RS_EPSZ );

		rs = skipcopy( tmp->a1,		sbuffer, 0, 	RS_SCSZ);
		rs = skipcopy( tmp->a2,		sbuffer, rs, 	RS_SCSZ);
		rs = skipcopy( tmp->pub->B2,	sbuffer, rs, 	RS_EPSZ);
		rs = skipcopy( tmp->pub->P1,	sbuffer, rs, 	RS_EPSZ);
		rs = skipcopy( tmp->pub->P2,	sbuffer, rs, 	RS_EPSZ);

		*out = (void *) tmp; return;
	}

	void pubstruct(const unsigned char *pbuffer, size_t plen, void **out){
		struct pubkey *tmp; size_t rs;
		//allocate memory for pubkey
		tmp = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//allocate memory for the elements
		tmp->B2 = (unsigned char *)malloc( RS_EPSZ );
		tmp->P1 = (unsigned char *)malloc( RS_EPSZ );
		tmp->P2 = (unsigned char *)malloc( RS_EPSZ );

		rs = skipcopy( tmp->B2,		pbuffer, 0, 	RS_EPSZ);
		rs = skipcopy( tmp->P1,		pbuffer, rs, 	RS_EPSZ);
		rs = skipcopy( tmp->P2,		pbuffer, rs, 	RS_EPSZ);

		*out = (void *) tmp; return;
	}

	void sigstruct(const unsigned char *obuffer, size_t olen, void **out){
		struct signat *tmp; size_t rs;
		//allocate memory for pubkey
		tmp = (struct signat *)malloc( sizeof(struct signat) );

		//allocate for components on signature struct
		tmp->s1= (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->s2= (unsigned char *)sodium_malloc( RS_SCSZ );
		tmp->x = (unsigned char *)malloc( RS_SCSZ );
		tmp->U = (unsigned char *)malloc( RS_EPSZ );
		tmp->B2= (unsigned char *)malloc( RS_EPSZ );
		tmp->P2 = (unsigned char *)malloc( RS_EPSZ );

		rs = skipcopy( tmp->s1,		obuffer, 0, 	RS_SCSZ);
		rs = skipcopy( tmp->s2,		obuffer, rs, 	RS_SCSZ);
		rs = skipcopy( tmp->x,		obuffer, rs, 	RS_SCSZ);
		rs = skipcopy( tmp->U,		obuffer, rs, 	RS_EPSZ);
		rs = skipcopy( tmp->B2,		obuffer, rs, 	RS_EPSZ);
		rs = skipcopy( tmp->P2,		obuffer, rs, 	RS_EPSZ);

		*out = (void *) tmp; return;
	}

	//destroy secret key
	void secdestroy(void *in){
		//key recast
		struct seckey *ri = (struct seckey *)in;
		//zero out the secret component
		sodium_memzero(ri->a1, RS_SCSZ);
		sodium_memzero(ri->a2, RS_SCSZ);

		//free memory
		sodium_free(ri->a1);
		sodium_free(ri->a2);
		pubdestroy(ri->pub);
		free(ri); return;
	}

	void pubdestroy(void *in){
		//key recast
		struct pubkey *ri = (struct pubkey *)in;
		//free up memory
		free(ri->B2);
		free(ri->P1);
		free(ri->P2);
		free(ri); return;
	}

	void sigdestroy(void *in){
		//key recast
		struct signat *ri = (struct signat *)in;
		//clear the components
		sodium_memzero(ri->s1, RS_SCSZ);
		sodium_memzero(ri->s2, RS_SCSZ);
		sodium_memzero(ri->x, RS_SCSZ);
		sodium_memzero(ri->U, RS_EPSZ);
		//free memory
		sodium_free(ri->s1);
		sodium_free(ri->s2);
		free(ri->x);
		free(ri->U);
		free(ri->B2);
		free(ri->P2);
		free(ri); return;
	}

	//debugging use only
	void secprint(void *in){
		struct seckey *ri = (struct seckey *)in;
		printf("a1:"); ucbprint(ri->a1, RS_SCSZ); printf("\n");
		printf("a2:"); ucbprint(ri->a2, RS_SCSZ); printf("\n");
		printf("B2:"); ucbprint(ri->pub->B2, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(ri->pub->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(ri->pub->P2, RS_EPSZ); printf("\n");
		return;
	}

	void pubprint(void *in){
		struct pubkey *ri = (struct pubkey *)in;
		printf("B2:"); ucbprint(ri->B2, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(ri->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(ri->P2, RS_EPSZ); printf("\n");
		return;
	}

	void sigprint(void *in){
		struct signat *ri = (struct signat *)in;
		printf("s1:"); ucbprint(ri->s1, RS_SCSZ); printf("\n");
		printf("s2:"); ucbprint(ri->s2, RS_SCSZ); printf("\n");
		printf("x :"); ucbprint(ri->x, RS_SCSZ); printf("\n");
		printf("U :"); ucbprint(ri->U, RS_EPSZ); printf("\n");
		printf("B2:"); ucbprint(ri->B2, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(ri->P2, RS_EPSZ); printf("\n");
		return;
	}

}
