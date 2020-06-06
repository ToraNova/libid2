/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 * abbreviated as ti25519 - TNC identification using 25519
 *
*/

// declaration includes
#include "tsi25519.hpp"
#include "utils/debug.h"

#include "internals/proto.hpp"
#include "internals/tnc/proto.hpp"

//mini socket library
#include "utils/simplesock.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * msk - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * mpk - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 * usk  - < 256 s >< 256 x >< 256 U >< 256 V >< 256 B > (does not need to store mpk anymore)
 *
 */
namespace ti25519{

	//IBI related functions
	int setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		return ts25519::keygen(pbuffer,plen,sbuffer,slen);
	}

	int extract(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		return ts25519::sign( sbuffer, slen, mbuffer, mlen, obuffer, olen );
	}

	int prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int csock
	){
		if(csock == -1){
			lerror("Invalid socket\n");
			return 1;
		}

		int rc;
		//parse the usk
		struct tnc::signat *usk;
		usk = tnc::sigstruct(obuffer, olen);

		debug("Sending ID string %s\n",mbuffer);
		rc = general::client::establish( csock, mbuffer, mlen );
		if(rc != 0){
			lerror("Failed to recv go-ahead (0x5a) byte\n");
			return 1;
		}
		debug("Go-Ahead received (0x5a), Starting PROVE protocol\n");

		rc = tnc::client::executeproto( csock, mbuffer, mlen, usk );

		//free up the usk
		sigdestroy(usk);
		return rc;
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int csock
	){
		if(csock == -1){lerror("Invalid socket\n");return 1;}

		int rc;
		unsigned char c[SCA], y[SCA], x[SCA];
		unsigned char LHS[ELE], RHS[ELE];
		unsigned char tmp1[ELE], tmp2[ELE];
		unsigned char hshe[crypto_core_ristretto255_HASHBYTES]; //hash
		unsigned char buf[CONN_MAXBF_SIZE] = {0};
		unsigned char ackp[1] = { CONN_ACK };
		crypto_hash_sha512_state eh_state;

		rc = recvbuf(csock, (char *)buf, CONN_MAXBF_SIZE);
		if( rc <= 0 ){
			lerror("Failed to recv ID string from prover\n");
			return 1;
		}
		*mlen = (size_t)rc;
		*mbuffer = (unsigned char *)malloc(*mlen);
		memcpy( *mbuffer, buf, *mlen );
		debug("ID string %s (%lu)\n",*mbuffer,*mlen);
		//echo back ox5a to begin protocol
		if( send(csock, ackp, 1, 0) < 0){lerror("Failed to echo back go-ahead (0x5a)\n");}
		debug("Go-Ahead sent (0x5a), Starting VERIFY protocol\n");
		memset(buf, 0, CONN_MAXBF_SIZE);

		rc = fixed_recvbuf(csock, (char *)buf, 3*ELE);
		if( rc <= 0 ){
			lerror("Failed to recv COMMIT from prover\n");
			return 1;
		}
		debug("Commit Received\n");

#ifdef DEBUG
		size_t j;
		printf("U :");
		for(j=0;j<ELE;j++){
			printf("%02X",buf[j]);
		}
		printf("\nV :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+ELE)[j]);
		}
		printf("\nT :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+2*ELE)[j]);
		}
		printf("\n");
#endif

		//---------------------SEND THE CHALLENGE
		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(c);
		sendbuf(csock, (char *)c , SCA);
		memset(y, 0, SCA);
		rc = fixed_recvbuf(csock, (char *)y, SCA);
		if( rc <= 0 ){
			lerror("Failed to recv RESPONSE from prover\n");
			return 1;
		}

		debug("Received Response...Computing Validity\n");

		//compute hash
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, *mbuffer, *mlen);
		crypto_hash_sha512_update( &eh_state, buf, ELE);
		crypto_hash_sha512_update( &eh_state, buf+ELE, ELE);
		crypto_hash_sha512_final( &eh_state, hshe);
		crypto_core_ristretto255_scalar_reduce( x, (const unsigned char *)hshe );

#ifdef DEBUG
		printf("c :");
		for(j=0;j<SCA;j++){
			printf("%02X",(c)[j]);
		}
		printf("\ny :");
		for(j=0;j<SCA;j++){
			printf("%02X",(y)[j]);
		}
		printf("\nx':");
		for(j=0;j<SCA;j++){
			printf("%02X",(x)[j]);
		}
		printf("\nB :");
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
		printf("\n");
#endif

		// yB = T + c( U' - xP1 )
		rc = crypto_scalarmult_ristretto255( LHS, y, pbuffer); // yB
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, x, pbuffer+ELE); // xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( tmp2, buf, tmp1); // U' - xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, c, tmp2); // c( U' - xP1 )
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( RHS, tmp1, buf+2*ELE); // T + c(U' - xP1)
		if( rc != 0 ) return rc; //abort if fail

		//check if tmp is equal to x from obuffer
		rc = crypto_verify_32( LHS, RHS );
		if( rc == 0 ){
			buf[0] = 0x00;
		}else{
			buf[0] = 0x01;
		}
		sendbuf(csock, (char *)buf , 1); //send back the results
		debug("Replied: %02X\n",buf[0]);

		return rc;
	}

	int verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		unsigned char tmp[ELE];
		unsigned char t[SCA], c[SCA], y[SCA], x[SCA];
		unsigned char tmp1[ELE], LHS[ELE], RHS[ELE], tmp2[ELE];
		unsigned char hshe[crypto_core_ristretto255_HASHBYTES]; //hash
		crypto_hash_sha512_state eh_state;

		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(t);
		//sample c (challenge)
		crypto_core_ristretto255_scalar_random(c);

		//compute response
		crypto_core_ristretto255_scalar_mul( tmp , c, obuffer ); //
		crypto_core_ristretto255_scalar_add( y, tmp, t ); // y = t + cs

		//compute hash, x
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, mbuffer, mlen);
		crypto_hash_sha512_update( &eh_state, obuffer+2*SCA, ELE);
		crypto_hash_sha512_update( &eh_state, obuffer+2*SCA+ELE, ELE);
		crypto_hash_sha512_final( &eh_state, hshe);
		crypto_core_ristretto255_scalar_reduce( x, (const unsigned char *)hshe );

		//T = tB
		rc = crypto_scalarmult_ristretto255( tmp, t, obuffer+2*SCA+2*ELE);

		// yB = T + c( U' - xP1 )
		rc = crypto_scalarmult_ristretto255( LHS, y, pbuffer); // yB
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, x, pbuffer+ELE); // xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( tmp2, obuffer+2*SCA, tmp1); // U' - xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, c, tmp2); // c( U' - xP1 )
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( RHS, tmp1, tmp); // T + c(U' - xP1)
		if( rc != 0 ) return rc; //abort if fail

		//check LHS == RHS
		rc = crypto_verify_32( LHS, RHS );
		return rc;
	}
}
