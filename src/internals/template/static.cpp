/*
 * <TEMPLATE> signature scheme key conversion functions
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


namespace <TEMPLATE>{

	struct seckey *randomkey(){
		int rc;
		//declare and allocate memory for key
		struct seckey *out;
		out = (struct seckey *)malloc( sizeof(struct seckey) );
		//allocate memory for pubkey
		out->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//TODO

		return out;
	}

	struct signat *signatgen(
		struct seckey *key,
		unsigned char *mbuffer, size_t mlen
	){
		int rc;
		//declare and allocate for signature struct
		struct signat *out;
		out = (struct signat *)malloc( sizeof( struct signat) );

		//TODO

		return out;
	}

	int signatchk(
		struct pubkey *par,
		struct signat *sig,
		unsigned char *mbuffer, size_t mlen
	){
		int rc;

		//TODO

		return rc;
	}

	unsigned char *hashexec(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *ubuffer,
		unsigned char *vbuffer
	){
		crypto_hash_sha512_state eh_state;
		unsigned char hshe[RS_HSSZ]; //hash
		unsigned char *out = (unsigned char *)malloc( RS_SCSZ );

		//TODO?

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
		free(hash);
	}

	size_t secserial(struct seckey *in, unsigned char **sbuffer, size_t *slen){
		size_t rs;
		//set size and allocate
		*slen = SKEY_SZ;
		*sbuffer = (unsigned char *)malloc( *(slen) );

		//TODO

		//a, B, P1, P2
		rs = copyskip( *sbuffer, in->a, 	0, 	RS_SCSZ);
		rs = copyskip( *sbuffer, in->pub->B, 	rs, 	RS_EPSZ);
		rs = copyskip( *sbuffer, in->pub->P1, 	rs, 	RS_EPSZ);
		rs = copyskip( *sbuffer, in->pub->P2, 	rs, 	RS_EPSZ);
		return rs;
	}

	size_t pubserial(struct seckey *in, unsigned char **pbuffer, size_t *plen){
		size_t rs;
		//set size and allocate
		*plen = PKEY_SZ;
		*pbuffer = (unsigned char *)malloc( *(plen) );

		//TODO

		return rs;
	}

	size_t sigserial(struct signat *in, unsigned char **obuffer, size_t *olen){
		size_t rs;
		//set size and allocate
		*olen = SGNT_SZ;
		*obuffer = (unsigned char *)malloc( *(olen) );

		//TODO

		return rs;
	}

	struct seckey *secstruct(unsigned char *sbuffer, size_t slen){
		struct seckey *out; size_t rs;
		//allocate memory for seckey
		out = (struct seckey *)malloc( sizeof(struct seckey));
		//allocate memory for pubkey
		out->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//TODO

		//allocate memory for the elements and scalars
		out->a = (unsigned char *)malloc( RS_SCSZ );
		out->pub->B = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P1 = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P2 = (unsigned char *)malloc( RS_EPSZ );

		rs = skipcopy( out->a,		sbuffer, 0, 	RS_SCSZ);
		rs = skipcopy( out->pub->B,	sbuffer, rs, 	RS_EPSZ);
		rs = skipcopy( out->pub->P1,	sbuffer, rs, 	RS_EPSZ);
		rs = skipcopy( out->pub->P2,	sbuffer, rs, 	RS_EPSZ);
		return out;
	}


	struct pubkey *pubstruct(unsigned char *pbuffer, size_t plen){
		struct pubkey *out; size_t rs;
		//allocate memory for pubkey
		out = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//TODO

		return out;
	}

	struct signat *sigstruct(unsigned char *obuffer, size_t olen){
		struct signat *out; size_t rs;
		//allocate memory for pubkey
		out = (struct signat *)malloc( sizeof(struct signat) );

		//TODO

		return out;
	}

	//destroy secret key
	void secdestroy(struct seckey *in){
		//zero out the secret component
		sodium_memzero(in->a, RS_SCSZ);

		//TODO

		//free memory
		free(in->a);
		pubdestroy(in->pub);
		free(in);
	}

	void pubdestroy(struct pubkey *in){
		//TODO
		//free up memory
		free(in->B);
		free(in->P1);
		free(in->P2);
		free(in);
	}

	void sigdestroy(struct signat *in){
		//TODO
		//clear the components
		sodium_memzero(in->s, RS_SCSZ);
		sodium_memzero(in->x, RS_SCSZ);
		sodium_memzero(in->U, RS_EPSZ);
		sodium_memzero(in->V, RS_EPSZ);
		//free memory
		free(in->s);
		free(in->x);
		free(in->U);
		free(in->V);
		free(in->B);
		free(in);
	}

	//debugging use only
	void secprint(struct seckey *in){
		//TODO
		printf("a :"); ucbprint(in->a, RS_SCSZ); printf("\n");
		printf("B :"); ucbprint(in->pub->B, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(in->pub->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(in->pub->P2, RS_EPSZ); printf("\n");
	}

	void pubprint(struct pubkey *in){
		//TODO
		printf("B :"); ucbprint(in->B, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(in->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(in->P2, RS_EPSZ); printf("\n");
	}

	void sigprint(struct signat *in){
		//TODO
		printf("s :"); ucbprint(in->s, RS_SCSZ); printf("\n");
		printf("x :"); ucbprint(in->x, RS_SCSZ); printf("\n");
		printf("U :"); ucbprint(in->U, RS_EPSZ); printf("\n");
		printf("V :"); ucbprint(in->V, RS_EPSZ); printf("\n");
		printf("B :"); ucbprint(in->B, RS_EPSZ); printf("\n");
	}

}
