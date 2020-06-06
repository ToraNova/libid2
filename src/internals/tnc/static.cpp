/*
 * TNC signature scheme key conversion functions
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include "static.hpp"

#include "../../utils/bufhelp.h"

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


namespace tnc{

	struct seckey *randomkey(){
		int rc;
		//declare and allocate memory for key
		struct seckey *out;
		out = (struct seckey *)malloc( sizeof(struct seckey) );

		//allocate memory for pubkey
		out->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//allocate memory for the elements and scalars
		out->a = (unsigned char *)malloc( RS_SCSZ );
		out->pub->B = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P1 = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P2 = (unsigned char *)malloc( RS_EPSZ );

		//sample a and B
		crypto_core_ristretto255_scalar_random( out->a );
		crypto_core_ristretto255_random( out->pub->B );

		rc = crypto_scalarmult_ristretto255(
				out->pub->P1,
				out->a,
				out->pub->B
				); // P1 = aB
		if( rc != 0 ) return NULL; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				out->pub->P2,
				out->a,
				out->pub->P1
				); // P2 = aP1
		if( rc != 0 ) return NULL; //abort if fail

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

		//nonce, r and hash
		unsigned char nonce[RS_SCSZ];

		//allocate for components
		out->s = (unsigned char *)malloc( RS_SCSZ );
		//out->x = (unsigned char *)malloc( RS_SCSZ ); //hashexec takes care
		out->U = (unsigned char *)malloc( RS_EPSZ );
		out->V = (unsigned char *)malloc( RS_EPSZ );
		out->B = (unsigned char *)malloc( RS_EPSZ );

		//sample r (MUST RANDOMIZE, else secret key a will be exposed)
		crypto_core_ristretto255_scalar_random(nonce);

		rc = crypto_scalarmult_ristretto255(
				out->U,
				nonce,
				key->pub->B
				); // U = rB
		if( rc != 0 ) return NULL; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				out->V,
				nonce,
				key->pub->P1
				); // V = rP1
		if( rc != 0 ) return NULL; //abort if fail

		//store B on the signature
		memcpy( out->B, key->pub->B, RS_EPSZ );

		out->x = hashexec(mbuffer, mlen, out->U, out->V);

		// s = r + xa
		crypto_core_ristretto255_scalar_mul( out->s , out->x, key->a );
		crypto_core_ristretto255_scalar_add( out->s, out->s, nonce );

		return out;
	}

	int signatchk(
		struct pubkey *par,
		struct signat *sig,
		unsigned char *mbuffer, size_t mlen
	){
		int rc;
		unsigned char tmp1[RS_EPSZ]; //tmp array
		unsigned char tmp2[RS_EPSZ]; //tmp array
		unsigned char tmp3[RS_EPSZ]; //tmp array
		unsigned char *xp;

		// U' = sB - xP1
		rc = crypto_scalarmult_ristretto255(
				tmp1,
				sig->s,
				par->B
				);
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255(
				tmp2,
				sig->x,
				par->P1
				);
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_sub( tmp3, tmp1, tmp2 ); //tmp3 U'
		if( rc != 0 ) return rc; //abort if fail

		// V' = sP1 - xP2
		rc = crypto_scalarmult_ristretto255(
				tmp1,
				sig->s,
				par->P1
				);
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255(
				tmp2,
				sig->x,
				par->P2
				);
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_sub( tmp2, tmp1, tmp2 ); //tmp4 V'
		if( rc != 0 ) return rc; //abort if fail

		xp = hashexec(mbuffer, mlen, tmp3, tmp2);

		//check if tmp is equal to x from obuffer
		rc = crypto_verify_32( xp, sig->x );

#ifdef DEBUG
		pubprint(par);
		sigprint(sig);
		printf("x':"); ucbprint(xp, RS_SCSZ); printf("\n");
		printf("U':"); ucbprint(tmp3, RS_EPSZ); printf("\n");
		printf("V':"); ucbprint(tmp2, RS_EPSZ); printf("\n");
#endif

		//free any allocated stuff
		hashfree(xp);

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

	void secserial(struct seckey *in, unsigned char **sbuffer, size_t *slen){
		*slen = 3*RS_EPSZ + RS_SCSZ;
		*sbuffer = (unsigned char *)malloc( *(slen) );

		//a, B, P1, P2
		memcpy( (*sbuffer), 		      in->a,		RS_SCSZ);
		memcpy( (*sbuffer+RS_SCSZ), 	      in->pub->B,	RS_EPSZ);
		memcpy( (*sbuffer+RS_SCSZ+RS_EPSZ),   in->pub->P1,	RS_EPSZ);
		memcpy( (*sbuffer+RS_SCSZ+RS_EPSZ*2), in->pub->P2,	RS_EPSZ);
		return;
	}

	void pubserial(struct seckey *in, unsigned char **pbuffer, size_t *plen){
		*plen = 3*RS_EPSZ;
		*pbuffer = (unsigned char *)malloc( *(plen) );

		//B, P1, P2
		memcpy( (*pbuffer), 	   	in->pub->B,	RS_EPSZ);
		memcpy( (*pbuffer+RS_EPSZ),	in->pub->P1,	RS_EPSZ);
		memcpy( (*pbuffer+RS_EPSZ*2),	in->pub->P2,	RS_EPSZ);
		return;
	}

	void sigserial(struct signat *in, unsigned char **obuffer, size_t *olen){
		*olen = 2*RS_SCSZ + 3*RS_EPSZ;
		*obuffer = (unsigned char *)malloc( *(olen) );

		//s,x,U,V,B
		memcpy( (*obuffer),			in->s,	RS_SCSZ);
		memcpy( (*obuffer+RS_SCSZ), 		in->x,	RS_SCSZ);
		memcpy( (*obuffer+RS_SCSZ*2), 	      	in->U,	RS_EPSZ);
		memcpy( (*obuffer+RS_SCSZ*2+RS_EPSZ),   in->V,	RS_EPSZ);
		memcpy( (*obuffer+RS_SCSZ*2+RS_EPSZ*2), in->B,	RS_EPSZ);
	}

	struct seckey *secstruct(unsigned char *sbuffer, size_t slen){
		struct seckey *out;
		//allocate memory for seckey
		out = (struct seckey *)malloc( sizeof(struct seckey));

		//allocate memory for pubkey
		out->pub = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//allocate memory for the elements and scalars
		out->a = (unsigned char *)malloc( RS_SCSZ );
		out->pub->B = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P1 = (unsigned char *)malloc( RS_EPSZ );
		out->pub->P2 = (unsigned char *)malloc( RS_EPSZ );

		memcpy( out->a,	      sbuffer,			RS_SCSZ);
		memcpy( out->pub->B,  sbuffer+RS_SCSZ, 		RS_EPSZ);
		memcpy( out->pub->P1, sbuffer+RS_SCSZ+RS_EPSZ, 	RS_EPSZ);
		memcpy( out->pub->P2, sbuffer+RS_SCSZ+RS_EPSZ*2,RS_EPSZ);
		return out;
	}


	struct pubkey *pubstruct(unsigned char *pbuffer, size_t plen){
		struct pubkey *out;
		//allocate memory for pubkey
		out = (struct pubkey *)malloc( sizeof(struct pubkey) );

		//allocate memory for the elements
		out->B = (unsigned char *)malloc( RS_EPSZ );
		out->P1 = (unsigned char *)malloc( RS_EPSZ );
		out->P2 = (unsigned char *)malloc( RS_EPSZ );

		memcpy( out->B,	 pbuffer,	  	RS_EPSZ);
		memcpy( out->P1, pbuffer+RS_EPSZ,  	RS_EPSZ);
		memcpy(	out->P2, pbuffer+RS_EPSZ*2,	RS_EPSZ);
		return out;
	}

	struct signat *sigstruct(unsigned char *obuffer, size_t olen){
		struct signat *out;
		//allocate memory for pubkey
		out = (struct signat *)malloc( sizeof(struct signat) );

		//allocate for components on signature struct
		out->s = (unsigned char *)malloc( RS_SCSZ );
		out->x = (unsigned char *)malloc( RS_SCSZ );
		out->U = (unsigned char *)malloc( RS_EPSZ );
		out->V = (unsigned char *)malloc( RS_EPSZ );
		out->B = (unsigned char *)malloc( RS_EPSZ );

		memcpy( out->s,	obuffer,	  		RS_SCSZ);
		memcpy( out->x,	obuffer+RS_SCSZ,		RS_SCSZ);
		memcpy( out->U,	obuffer+RS_SCSZ*2,		RS_EPSZ);
		memcpy( out->V,	obuffer+RS_SCSZ*2+RS_EPSZ,	RS_EPSZ);
		memcpy( out->B,	obuffer+RS_SCSZ*2+RS_EPSZ*2,	RS_EPSZ);
		return out;
	}

	//destroy secret key
	void secdestroy(struct seckey *in){
		//zero out the secret component
		sodium_memzero(in->a, RS_SCSZ);

		//free memory
		free(in->a);
		pubdestroy(in->pub);
		free(in);
	}

	void pubdestroy(struct pubkey *in){
		//free up memory
		free(in->B);
		free(in->P1);
		free(in->P2);
		free(in);
	}

	void sigdestroy(struct signat *in){
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
		printf("a :"); ucbprint(in->a, RS_SCSZ); printf("\n");
		printf("B :"); ucbprint(in->pub->B, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(in->pub->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(in->pub->P2, RS_EPSZ); printf("\n");
	}

	void pubprint(struct pubkey *in){
		printf("B :"); ucbprint(in->B, RS_EPSZ); printf("\n");
		printf("P1:"); ucbprint(in->P1, RS_EPSZ); printf("\n");
		printf("P2:"); ucbprint(in->P2, RS_EPSZ); printf("\n");
	}

	void sigprint(struct signat *in){
		printf("s :"); ucbprint(in->s, RS_SCSZ); printf("\n");
		printf("x :"); ucbprint(in->x, RS_SCSZ); printf("\n");
		printf("U :"); ucbprint(in->U, RS_EPSZ); printf("\n");
		printf("V :"); ucbprint(in->V, RS_EPSZ); printf("\n");
		printf("B :"); ucbprint(in->B, RS_EPSZ); printf("\n");
	}

}
