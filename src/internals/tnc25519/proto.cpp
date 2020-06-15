/*
 * internals/tnc25519/proto.cpp - id2 library
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
 * TNC signature scheme key conversion functions
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include "static.hpp"
#include "proto.hpp"

// include general prototype and macro
#include "../proto.hpp"
#include "../cmacro.h"

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

namespace tnc25519{

	int signatprv(
		int sock,
		void *vusk,
		unsigned char *mbuffer, size_t mlen
	){
		//socket check and key recast
		if(sock == -1){return 1;}
		struct signat *usk = (struct signat *)vusk;
		int rc;

		unsigned char t[RS_SCSZ], c[RS_SCSZ], y[RS_SCSZ];
		unsigned char tmp[RS_SCSZ] = {0};
		unsigned char buf[TS_MAXSZ] = {0};

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
			lerror("Failed to compute COMMIT\n");
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
	sigprint(usk);
	printf("t :"); ucbprint(t, RS_SCSZ); printf("\n");
	printf("T :"); ucbprint(buf+2*RS_EPSZ, RS_EPSZ); printf("\n");
	printf("c :"); ucbprint(c, RS_SCSZ); printf("\n");
	printf("y :"); ucbprint(y, RS_SCSZ); printf("\n");
#endif

		//PREVENT RESET ATTACKS, clear the commit
		memset(t, 0, RS_SCSZ); //zero t
		memset(buf, 0, 3*RS_EPSZ); //zero U,V and T
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

	int signatvrf(
		int sock,
		void *vpar,
		unsigned char *mbuffer, size_t mlen
	){
		//socket check and key recast
		if(sock == -1){return 1;}
		struct pubkey *par = (struct pubkey *)vpar;

		int rc;
		unsigned char c[RS_SCSZ], y[RS_SCSZ], *xp;
		unsigned char LHS[RS_EPSZ], RHS[RS_EPSZ];
		unsigned char tmp1[RS_EPSZ], tmp2[RS_EPSZ];
		unsigned char buf[TS_MAXSZ] = {0};

		//--------------------------------------------------------
		//--------------RECEIVE COMMIT FROM PROVER
		//CMT <- U',V' T
		rc = fixed_recvbuf(sock, (char *)buf, 3*RS_EPSZ);
		if( rc <= 0 ){
			lerror("Failed to recv COMMIT from prover\n");
			return 1;
		}

		//--------------------------------------------------------
		//---------------------SEND THE CHALLENGE
		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(c);
		sendbuf(sock, (char *)c , RS_SCSZ);
		memset(y, 0, RS_SCSZ);
		//--------------------------------------------------------
		//---------------------RECEIVE RESPONSE
		rc = fixed_recvbuf(sock, (char *)y, RS_SCSZ);
		if( rc <= 0 ){
			lerror("Failed to recv RESPONSE from prover\n");
			return 1;
		}

		//hash
		xp = hashexec(mbuffer, mlen, buf, (buf+RS_EPSZ) );

#ifdef DEBUG
pubprint(par);
printf("U :"); ucbprint( buf, RS_EPSZ ); printf("\n");
printf("V :"); ucbprint( buf+RS_EPSZ, RS_EPSZ ); printf("\n");
printf("T :"); ucbprint( buf+RS_EPSZ*2, RS_EPSZ ); printf("\n");
printf("c :"); ucbprint( c, RS_SCSZ ); printf("\n");
printf("y :"); ucbprint( y, RS_SCSZ ); printf("\n");
printf("x':"); ucbprint( xp, RS_SCSZ ); printf("\n");
#endif

		// yB = T + c( U' - xP1 )
		rc = crypto_scalarmult_ristretto255( tmp1, xp, par->P1); // xP1
		//zero and free
		hashfree(xp);
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( LHS, y, par->B); // yB
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( tmp2, buf, tmp1); // U' - xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, c, tmp2); // c( U' - xP1 )
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( RHS, tmp1, buf+2*RS_EPSZ);// T + c(U' - xP1)
		if( rc != 0 ) return rc; //abort if fail

		//check if tmp is equal to x from obuffer
		rc = crypto_verify_32( LHS, RHS );
		if( rc == 0 ){
			buf[0] = 0x00;
		}else{
			buf[0] = 0x01;
		}
		sendbuf(sock, (char *)buf , 1); //send back the results
		debug("Replied: %02X\n",buf[0]);

		return rc;
	}

//general (non client or server namespace)

	int prototest(
		void *vpar,
		void *vusk,
		unsigned char *mbuffer, size_t mlen
	){
		//key recast
		struct pubkey *par = (struct pubkey *)vpar;
		struct signat *usk = (struct signat *)vusk;
		int rc;
		unsigned char tmp[RS_EPSZ];
		unsigned char t[RS_SCSZ], c[RS_SCSZ], y[RS_SCSZ], *xp;
		unsigned char tmp1[RS_EPSZ], LHS[RS_EPSZ], RHS[RS_EPSZ], tmp2[RS_EPSZ];

		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(t);
		//sample c (challenge)
		crypto_core_ristretto255_scalar_random(c);

		//compute response
		crypto_core_ristretto255_scalar_mul( tmp , c, usk->s ); //
		crypto_core_ristretto255_scalar_add( y, tmp, t ); // y = t + cs

		xp = hashexec(mbuffer, mlen, usk->U, usk->V);

		//T = tB
		rc = crypto_scalarmult_ristretto255( tmp, t, usk->B);

		// yB = T + c( U' - xP1 )
		rc = crypto_scalarmult_ristretto255( LHS, y, par->B); // yB
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, xp, par->P1); // xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( tmp2, usk->U, tmp1); // U' - xP1
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_scalarmult_ristretto255( tmp1, c, tmp2); // c( U' - xP1 )
		if( rc != 0 ) return rc; //abort if fail
		rc = crypto_core_ristretto255_add( RHS, tmp1, tmp); // T + c(U' - xP1)
		if( rc != 0 ) return rc; //abort if fail

		//check LHS == RHS
		rc = crypto_verify_32( LHS, RHS );

		hashfree(xp);

		return rc;
	}

}
