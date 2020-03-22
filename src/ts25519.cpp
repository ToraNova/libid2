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
		int rc;
		//pbufer stores B, P1 and P2 (MAIN PUBLIC KEY)
		*plen = 3*ELE;
		*pbuffer = (unsigned char *)malloc( *(plen) );
		//sbuffer stores a, B, P1 and P2 (SECRET KEY, also contains PUBLIC COMPONENTS)
		//a is the main secret
		*slen = SCA+(*plen);
		*sbuffer = (unsigned char *)malloc( *(slen) );

		//sample generator
		//generate random 32bit scalar Zq
		crypto_core_ristretto255_scalar_random(*sbuffer); //sample a
		crypto_core_ristretto255_random(*pbuffer); //sample B

		rc = crypto_scalarmult_ristretto255(
				(*pbuffer+ELE),
				*sbuffer,
				*pbuffer
				); // P1 = aB
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				(*pbuffer+2*ELE),
				*sbuffer,
				(*pbuffer+ELE)
				); // P2 = aP1 = aaB
		if( rc != 0 ) return rc; //abort if fail

		memcpy(
			(*sbuffer+SCA),
			*pbuffer,
			ELE
			); //copy B into sbuffer

		memcpy(
			(*sbuffer+SCA+ELE),
			(*pbuffer+ELE),
			ELE
			); //copy P1 into sbuffer

		memcpy(
			(*sbuffer+SCA+2*ELE),
			(*pbuffer+2*ELE),
			ELE
			); //copy P2 into sbuffer

#ifdef DEBUG
		size_t i;
		printf("a :");
		for(i=0;i<SCA;i++){
			printf("%02X",(*sbuffer)[i]);
		}
		printf("\nB :");
		for(i=0;i<ELE;i++){
			printf("%02X",(*sbuffer+SCA)[i]);
		}
		printf("\nP1:");
		for(i=0;i<ELE;i++){
			printf("%02X",(*sbuffer+SCA+ELE)[i]);
		}
		printf("\nP2:");
		for(i=0;i<ELE;i++){
			printf("%02X",(*sbuffer+SCA+2*ELE)[i]);
		}
		printf("\n");
#endif
		return 0;
	}

	int sign(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		int rc;
		unsigned char r[SCA]; //tmp array
		unsigned char tmp[SCA]; //tmp array
		unsigned char hshe[crypto_core_ristretto255_HASHBYTES]; //hash
		crypto_hash_sha512_state eh_state;

		*olen = 2*SCA+3*ELE; //s, x and U' V' B
		*obuffer = (unsigned char *)calloc( *(olen), sizeof(unsigned char) );

		//sample r (MUST RANDOMIZE, else secret key a will be exposed)
		crypto_core_ristretto255_scalar_random(r);

		rc = crypto_scalarmult_ristretto255(
				(*obuffer+2*SCA),
				r,
				(sbuffer+SCA)
				); // U = rB
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				(*obuffer+2*SCA+ELE),
				r,
				(sbuffer+SCA+ELE)
				); // V = rP1
		if( rc != 0 ) return rc; //abort if fail
		memcpy( (*obuffer+2*SCA+2*ELE), (sbuffer+SCA), ELE ); //store B on the signature (usk)

		//compute hash
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, mbuffer, mlen);
		crypto_hash_sha512_update( &eh_state, (*obuffer+2*SCA), ELE);
		crypto_hash_sha512_update( &eh_state, (*obuffer+2*SCA+ELE), ELE);
		crypto_hash_sha512_final( &eh_state, hshe);
		crypto_core_ristretto255_scalar_reduce( (*obuffer+SCA), (const unsigned char *)hshe );
		crypto_core_ristretto255_scalar_mul( tmp , (*obuffer+SCA), sbuffer ); //
		crypto_core_ristretto255_scalar_add( *obuffer, tmp, r ); // s = r + xa

#ifdef DEBUG
		size_t i;
		printf("s :");
		for(i=0;i<SCA;i++){
			printf("%02X",(*obuffer)[i]);
		}
		printf("\nx :");
		for(i=0;i<SCA;i++){
			printf("%02X",(*obuffer+SCA)[i]);
		}
		printf("\nU :");
		for(i=0;i<ELE;i++){
			printf("%02X",(*obuffer+2*SCA)[i]);
		}
		printf("\nV :");
		for(i=0;i<ELE;i++){
			printf("%02X",(*obuffer+2*SCA+ELE)[i]);
		}
		printf("\n");
#endif
		return 0;
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		unsigned char tmp[SCA]; //tmp array
		unsigned char hshe[crypto_core_ristretto255_HASHBYTES]; //hash
		crypto_hash_sha512_state eh_state;

		unsigned char tmp1[ELE]; //tmp array
		unsigned char tmp2[ELE]; //tmp array
		unsigned char tmp3[ELE]; //tmp array
		unsigned char tmp4[ELE]; //tmp array
		// U' = sB - xP1
		rc = crypto_scalarmult_ristretto255(
				tmp1,
				(obuffer),
				(pbuffer)
				);
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				tmp2,
				(obuffer+SCA),
				(pbuffer+ELE)
				);
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_core_ristretto255_sub( tmp3, tmp1, tmp2 ); //tmp3 U'
		if( rc != 0 ) return rc; //abort if fail

		// V' = sP1 - xP2
		rc = crypto_scalarmult_ristretto255(
				tmp1,
				(obuffer),
				(pbuffer+ELE)
				);
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_scalarmult_ristretto255(
				tmp2,
				(obuffer+SCA),
				(pbuffer+2*ELE)
				);
		if( rc != 0 ) return rc; //abort if fail

		rc = crypto_core_ristretto255_sub( tmp4, tmp1, tmp2 ); //tmp4 V'
		if( rc != 0 ) return rc; //abort if fail

		//compute hash
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, mbuffer, mlen);
		crypto_hash_sha512_update( &eh_state, tmp3, ELE);
		crypto_hash_sha512_update( &eh_state, tmp4, ELE);
		crypto_hash_sha512_final( &eh_state, hshe);
		crypto_core_ristretto255_scalar_reduce( tmp, (const unsigned char *)hshe );

		//check if tmp is equal to x from obuffer
		rc = crypto_verify_32( tmp, (obuffer+SCA) );

#ifdef DEBUG
		size_t j;
		printf("B :");
		for(j=0;j<ELE;j++){
			printf("%02X",(pbuffer)[j]);
		}
		printf("\nP1:");
		for(j=0;j<ELE;j++){
			printf("%02X",(pbuffer+ELE)[j]);
		}
		printf("\nP2:");
		for(j=0;j<ELE;j++){
			printf("%02X",(pbuffer+2*ELE)[j]);
		}
		printf("\ns :");
		for(j=0;j<SCA;j++){
			printf("%02X",(obuffer)[j]);
		}
		printf("\nU :");
		for(j=0;j<ELE;j++){
			printf("%02X",(obuffer+2*SCA)[j]);
		}
		printf("\nU':");
		for(j=0;j<ELE;j++){
			printf("%02X",(tmp3)[j]);
		}
		printf("\nV :");
		for(j=0;j<ELE;j++){
			printf("%02X",(obuffer+2*SCA+ELE)[j]);
		}
		printf("\nV':");
		for(j=0;j<ELE;j++){
			printf("%02X",(tmp4)[j]);
		}
		printf("\nx :");
		for(j=0;j<SCA;j++){
			printf("%02X",(obuffer+SCA)[j]);
		}
		printf("\nx':");
		for(j=0;j<SCA;j++){
			printf("%02X",(tmp)[j]);
		}
		printf("\n");
#endif
		return rc; //return result
	}
}
