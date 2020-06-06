/*
 * TNC signature scheme key conversion functions
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include "static.hpp"
#include "proto.hpp"

// include general prototype
#include "../proto.hpp"

//mini socket library
#include "../../utils/bufhelp.h"
#include "../../utils/debug.h"
#include "../../utils/simplesock.h"

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <cstring>

namespace tnc{

namespace client{

int executeproto(
	int sock,
	unsigned char *mbuffer, size_t mlen,
	struct signat *usk
){
	if(sock == -1){return -1;}
	int rc;
	unsigned char t[RS_SCSZ], c[RS_SCSZ], y[RS_SCSZ];
	unsigned char tmp[RS_SCSZ] = {0};
	unsigned char buf[CONN_MAXBF_SIZE] = {0};

	//sample t (commit secret)
	crypto_core_ristretto255_scalar_random(t);

	//--------------------------------------------------------
	//--------------COMPUTE AND SEND COMMIT
	//CMT <- U',V' T
	// T = tB
	memcpy( buf, usk->U, RS_EPSZ);
	memcpy( buf+RS_EPSZ, usk->V, RS_EPSZ);
	rc = crypto_scalarmult_ristretto255( buf+2*RS_EPSZ, t, usk->B);
	if( rc != 0 ){
		//abort if fail
		lerror("Failed to compute commit\n");
		return 1;
	}
	sendbuf( sock, (char *)buf , 3*RS_EPSZ); //send CMT

	//--------------------------------------------------------
	//--------------RECEIVE CHALLENGE
	memset(c, 0, RS_SCSZ); memset(y, 0, RS_SCSZ);
	rc = fixed_recvbuf(sock, (char *)c, RS_SCSZ);
	if( rc <= 0 ){
		lerror("Failed to recv CHALLENGE from verifier\n");
		return 1;
	}

	//--------------COMPUTE AND SEND RESPONSE
	// y = t + cs
	crypto_core_ristretto255_scalar_mul( tmp, c, usk->s ); //
	crypto_core_ristretto255_scalar_add( y, tmp, t );

#ifdef DEBUG
printsig(usk);
printf("t :"); ucbprint(t, RS_SCSZ); printf("\n");
printf("c :"); ucbprint(c, RS_SCSZ); printf("\n");
printf("y :"); ucbprint(y, RS_SCSZ); printf("\n");
#endif

	memset(t, 0, RS_SCSZ); //PREVENT RESET ATTACKS -- FREE t
	sendbuf(sock, (char *)y , RS_SCSZ);


	buf[0] = 0x01;
	rc = fixed_recvbuf(sock, (char *)buf, 1); //receive final result
	if( rc <= 0 ){
		lerror("Failed to recv RESULT from verifier\n");
		return 1;
	}
	debug("Received: %02X\n",buf[0]);

	//return OK
	return (int) buf[0];
}

}

namespace server{

int executeproto(
	int sock,
	struct pubkey *par,
	unsigned char **mbuffer, size_t *mlen
){

}

}

}
