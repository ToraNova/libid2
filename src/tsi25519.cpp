/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 *
 * Contains implementation of TNC signature scheme
 * and TNC IBI
 * abbreviated as tsi25519 - TNC signature and identification using 25519
*/

// declaration includes
#include "tsi25519.hpp"
#include "debug.h"

//mini socket library
#include "simplesock.h"
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

using namespace std;

#define ELE crypto_core_ristretto255_BYTES
#define SCA crypto_core_ristretto255_SCALARBYTES

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * skey - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * pkey - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 *
 */
namespace tsi25519
{
	//standard signatures
	namespace ss{

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
		printf("a  :");
		for(i=0;i<SCA;i++){
			printf("%02X",(*sbuffer)[i]);
		}
		printf("\nB  :");
		for(i=0;i<ELE;i++){
			printf("%02X",(*sbuffer+SCA)[i]);
		}
		printf("\nP1 :");
		for(i=0;i<ELE;i++){
			printf("%02X",(*sbuffer+SCA+ELE)[i]);
		}
		printf("\nP2 :");
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

		*olen = 2*SCA+3*ELE; //s, x and U' V'
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
		//s is on first 32byte on obuffer
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
		//crypto_hash_sha512_update( &eh_state, obuffer+2*SCA, ELE);
		//crypto_hash_sha512_update( &eh_state, obuffer+2*SCA+ELE, ELE);
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
		printf("signature :");
		for(j=0;j<SCA;j++){
			printf("%02X",(obuffer)[j]);
		}
		printf("\n");
#endif
		return rc; //return result
	}

	}

	//IBI related functions
	namespace ibi{

	int setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		return ss::keygen(pbuffer,plen,sbuffer,slen);
	}

	int extract(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		return ss::sign( sbuffer, slen, mbuffer, mlen, obuffer, olen );
	}

	/*
	 * Don't touch the following until security is proven
	 */
	int prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int port, const char *srv,
		int timeout
	){

		short tsock;
		int rc;
		unsigned char t[SCA];
		unsigned char c[SCA];
		unsigned char y[SCA];
		unsigned char tmp[SCA] = {0};
		unsigned char buf[CONN_MAXBF_SIZE] = {0};

		//Create socket
		tsock = sockgen(0);
		if(tsock == -1){lerror("Socket creation failed\n");return 1;}

		//Attempt to connect
		debug("Attempting to connect to %s:%d\n",srv,port);
		if( sockconn(tsock, srv, port) < 0){lerror("Failed to connect to verifier\n");return 1;}
		debug("Connection established with %s:%d\n",srv,port);
		debug("Sending ID string %s\n",mbuffer);
		sendbuf(tsock, (char *)mbuffer , mlen, timeout);
		//await byte 0x5a before proceeding with protocol
		if( recv(tsock, buf, 1, 0) < 0 || buf[0] != 0x5a){
			lerror("Failed to recv go-ahead (0x5a) byte\n");
			return 1;
		}
		debug("Go-Ahead received (0x5a), Starting PROVE protocol");
		memset(buf, 0, CONN_MAXBF_SIZE); //reset

		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(t);

		//--------------COMPUTE AND SEND COMMIT
		// T = tB
		memcpy( buf, obuffer+2*SCA, ELE);
		memcpy( buf+ELE, obuffer+2*SCA+ELE, ELE); //CMT <- U',V' T
		rc = 1;
		rc = crypto_scalarmult_ristretto255( buf+2*ELE, t, obuffer+2*SCA+2*ELE);
		if( rc != 0 ) return rc; //abort if fail

#ifdef DEBUG
		size_t j;
		printf("U  :");
		for(j=0;j<ELE;j++){
			printf("%02X",buf[j]);
		}
		printf("\nV  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+ELE)[j]);
		}
		printf("\nT  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+2*ELE)[j]);
		}
		printf("\nB  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(obuffer+2*SCA+2*ELE)[j]);
		}
		printf("\n");
#endif

		sendbuf( tsock, (char *)buf , 3*ELE, timeout); //send CMT

		//--------------RECEIVE CHALLENGE
		memset(c, 0, SCA); memset(y, 0, SCA);
		rc = 1;
		rc = recvbuf(tsock, (char *)c, SCA, 0);
		if( rc < 0 ){
			lerror("Failed to recv CHALLENGE from verifier\n");
			return 1;
		}

		//--------------COMPUTE AND SEND RESPONSE
		crypto_core_ristretto255_scalar_mul( tmp , c, obuffer ); //
		crypto_core_ristretto255_scalar_add( y, tmp, t ); // y = t + cs
		sendbuf(tsock, (char *)y , SCA, timeout);

#ifdef DEBUG
		printf("c  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(c)[j]);
		}
		printf("\ny  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(y)[j]);
		}
		printf("\ns  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(obuffer)[j]);
		}
		printf("\n");
#endif

		buf[0] = 0x01;
		rc = recv(tsock, buf, 1, 0); //receive final result
		if( rc < 0 ){
			lerror("Failed to recv RESULT from verifier\n");
			return 1;
		}
		//close socket
		close(tsock);
		debug("Received: %02X",buf[0]);

		//return OK
		return (int) buf[0];
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	){
		struct sockaddr_in cli;
		int rc;
		unsigned char c[SCA], y[SCA], x[SCA];
		unsigned char LHS[ELE], RHS[ELE];
		unsigned char tmp1[ELE], tmp2[ELE];
		unsigned char hshe[crypto_core_ristretto255_HASHBYTES]; //hash
		crypto_hash_sha512_state eh_state;

		short ssock,csock; //server socket and client socket
		int cli_len = sizeof(struct sockaddr_in);
		unsigned char buf[CONN_MAXBF_SIZE] = {0};
		unsigned char ackp[1] = { CONN_ACK };

		//Create socket
		ssock = sockgen(0);
		if(ssock == -1){lerror("Socket creation failed\n");return 1;}
		//bind the socket
		if(sockbind(ssock,port, 1) < 0){lerror("Port bind failed\n");return 1;}

		//listen for incoming conn
		debug("Listening for verification attempts on port %d",port);
		listen(ssock, 1);

		csock = accept( ssock, (struct sockaddr *)&cli, (socklen_t*)&cli_len);
		if(csock < 0){lerror("Connection failed to establish\n");return 1;}
		debug("Connection established");
		rc = recv(csock, buf, CONN_MAXBF_SIZE, 0);
		if( rc < 0 ){
			lerror("Failed to recv ID string from prover\n");
			return 1;
		}
		*mlen = (size_t)rc;
		*mbuffer = (unsigned char *)malloc(*mlen);
		memcpy( *mbuffer, buf, *mlen );
		debug("ID string %s (%lu)",*mbuffer,*mlen);
		//echo back ox5a to begin protocol
		if( send(csock, ackp, 1, 0) < 0){lerror("Failed to echo back go-ahead (0x5a)\n");}
		debug("Go-Ahead sent (0x5a), Starting VERIFY protocol");
		memset(buf, 0, CONN_MAXBF_SIZE);


		rc = recvbuf(csock, (char *)buf, 3*ELE, 0);
		if( rc < 0 ){
			lerror("Failed to recv COMMIT from prover\n");
			return 1;
		}
		debug("Commit Received");

#ifdef DEBUG
		size_t j;
		printf("U  :");
		for(j=0;j<ELE;j++){
			printf("%02X",buf[j]);
		}
		printf("\nV  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+ELE)[j]);
		}
		printf("\nT  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(buf+2*ELE)[j]);
		}
		printf("\n");
#endif

		//---------------------SEND THE CHALLENGE
		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(c);
		sendbuf(csock, (char *)c , SCA, timeout);
		memset(y, 0, SCA);
		rc = recvbuf(csock, (char *)y, SCA, 0);
		if( rc < 0 ){
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

#ifdef EDEBUG
		printf("c  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(c)[j]);
		}
		printf("\ny  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(y)[j]);
		}
		printf("\nx  :");
		for(j=0;j<SCA;j++){
			printf("%02X",(x)[j]);
		}
		printf("\nB  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(pbuffer)[j]);
		}
		printf("\nP1  :");
		for(j=0;j<ELE;j++){
			printf("%02X",(pbuffer+ELE)[j]);
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
		sendbuf(csock, (char *)buf , 1, timeout); //send back the results

		debug("Replied: %02X\n",buf[0]);

		close(csock);
		close(ssock);
		return rc;
	}

	int verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		return 0;
	}

	}
}
