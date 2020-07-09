/*
 * internals/twn25519/proto.cpp - id2 library
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
 * twn25519 :TODO please edit the description
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

namespace twn25519{

	int signatprv(
		int sock,
		void *vusk,
		const unsigned char *mbuffer, size_t mlen
	){
		//socket check and key recast
		if(sock == -1){return 1;}
		struct signat *usk = (struct signat *)vusk;
		int rc;

		//--------------------------TODO START
		unsigned char t1[RS_SCSZ], t2[RS_SCSZ], c[RS_SCSZ], y[2*RS_SCSZ];
		unsigned char tb1[RS_EPSZ], tb2[RS_EPSZ];
		unsigned char buf[TS_MAXSZ] = {0};

		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(t1);
		crypto_core_ristretto255_scalar_random(t2);

		//--------------------------------------------------------
		//--------------COMPUTE AND SEND COMMIT
		//CMT <- U',V' T
		// T = tB
		rc = 0;
		rc += crypto_scalarmult_ristretto255_base( tb1, t1);
		rc += crypto_scalarmult_ristretto255( tb2, t2, usk->B2);
		rc += crypto_core_ristretto255_add( buf, tb1, tb2);
		if( rc != 0 ){
			//abort if fail
			lerror("Failed to compute COMMIT\n");
			return 1;
		}
		memcpy( buf+RS_EPSZ, usk->U, RS_EPSZ);
		sendbuf( sock, (char *)buf , 2*RS_EPSZ); //send CMT

		//--------------------------------------------------------
		//--------------RECEIVE CHALLENGE
		memset(c, 0, RS_SCSZ); memset(y, 0, 2*RS_SCSZ);
		rc = fixed_recvbuf(sock, (char *)c, RS_SCSZ);
		if( rc <= 0 ){
			lerror("Failed to recv CHALLENGE from verifier\n");
			return 1;
		}

		//--------------COMPUTE AND SEND RESPONSE
		// y = t + cs
		crypto_core_ristretto255_scalar_mul( y, c, usk->s1 ); //
		crypto_core_ristretto255_scalar_add( y, y, t1 );
		crypto_core_ristretto255_scalar_mul( y+RS_SCSZ, c, usk->s2 ); //
		crypto_core_ristretto255_scalar_add( y+RS_SCSZ, y+RS_SCSZ, t2 );

#ifdef DEBUG
	sigprint(usk);
	printf("t1:"); ucbprint(t1, RS_SCSZ); printf("\n");
	printf("t2:"); ucbprint(t2, RS_SCSZ); printf("\n");
	printf("T :"); ucbprint(buf, RS_SCSZ); printf("\n");
	printf("c :"); ucbprint(c, RS_SCSZ); printf("\n");
	printf("y1:"); ucbprint(y, RS_SCSZ); printf("\n");
	printf("y2:"); ucbprint(y+RS_SCSZ, RS_SCSZ); printf("\n");
#endif

		//PREVENT RESET ATTACKS, clear the commit trace
		memset(t1, 0, RS_SCSZ); //zero t1
		memset(t2, 0, RS_SCSZ); //zero t2
		memset(tb1, 0, RS_EPSZ); //zero tb1
		memset(tb2, 0, RS_EPSZ); //zero tb2
		memset(buf, 0, TS_MAXSZ); //zero the buffer
		sendbuf(sock, (char *)y , 2*RS_SCSZ);

		buf[0] = 0x01;
		rc = fixed_recvbuf(sock, (char *)buf, 1); //receive final result
		if( rc <= 0 ){
			lerror("Failed to recv RESULT from verifier\n");
			return 1;
		}
		debug("Received: %02X\n",buf[0]);
		//--------------------------TODO END

		return (int) buf[0];
	}

	int signatvrf(
		int sock,
		void *vpar,
		const unsigned char *mbuffer, size_t mlen
	){
		//socket check and key recast
		if(sock == -1){return 1;}
		struct pubkey *par = (struct pubkey *)vpar;
		int rc;

		//--------------------------TODO START
		unsigned char c[RS_SCSZ], y[2*RS_SCSZ], *xp;
		unsigned char LHS[RS_EPSZ], RHS[RS_EPSZ];
		unsigned char tmp1[RS_EPSZ], tmp2[RS_EPSZ];
		unsigned char buf[TS_MAXSZ] = {0};

		//--------------------------------------------------------
		//--------------RECEIVE COMMIT FROM PROVER
		//CMT <- T, U'
		rc = fixed_recvbuf(sock, (char *)buf, 2*RS_EPSZ);
		if( rc <= 0 ){
			lerror("Failed to recv COMMIT from prover\n");
			return 1;
		}

		//--------------------------------------------------------
		//---------------------SEND THE CHALLENGE
		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(c);
		sendbuf(sock, (char *)c , RS_SCSZ);
		memset(y, 0, 2*RS_SCSZ);
		//--------------------------------------------------------
		//---------------------RECEIVE RESPONSE
		rc = fixed_recvbuf(sock, (char *)y, 2*RS_SCSZ);
		if( rc <= 0 ){
			lerror("Failed to recv RESPONSE from prover\n");
			return 1;
		}

		//hash
		xp = hashexec(mbuffer, mlen, buf+RS_EPSZ, par->P);

#ifdef DEBUG
pubprint(par);
printf("U :"); ucbprint( buf+RS_EPSZ, RS_EPSZ ); printf("\n");
printf("T :"); ucbprint( buf, RS_EPSZ ); printf("\n");
printf("c :"); ucbprint( c, RS_SCSZ ); printf("\n");
printf("y1:"); ucbprint( y, RS_SCSZ ); printf("\n");
printf("y2:"); ucbprint( y+RS_SCSZ, RS_SCSZ ); printf("\n");
printf("x':"); ucbprint( xp, RS_SCSZ ); printf("\n");
#endif

		// yB = T + c( U' - xP1 )
		rc = 0;
		rc += crypto_scalarmult_ristretto255( tmp1, xp, par->P); // xP1
		//zero and free
		hashfree(xp);

		rc += crypto_scalarmult_ristretto255_base( LHS, y);
		rc += crypto_scalarmult_ristretto255( tmp2, y+RS_SCSZ, par->B2);
		rc += crypto_core_ristretto255_add( LHS, LHS, tmp2); //z1G1, z2G2 LHS

		rc += crypto_core_ristretto255_sub( tmp2, buf+RS_EPSZ, tmp1); // U' - xP
		rc += crypto_scalarmult_ristretto255( tmp1, c, tmp2); // c( U' - xP )
		rc += crypto_core_ristretto255_add( RHS, tmp1, buf);// T + c(U' - xP)
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
		//--------------------------TODO END

		return rc;
	}

//general (non client or server namespace)

	int prototest(
		void *vpar,
		void *vusk,
		const unsigned char *mbuffer, size_t mlen
	){
		//key recast
		struct pubkey *par = (struct pubkey *)vpar;
		struct signat *usk = (struct signat *)vusk;
		int rc;

		//--------------------------TODO START
		unsigned char tmp[RS_EPSZ];
		unsigned char t1[RS_SCSZ], t2[RS_SCSZ], c[RS_SCSZ], y[2*RS_SCSZ], *xp;
		unsigned char tmp1[RS_EPSZ], LHS[RS_EPSZ], RHS[RS_EPSZ], tmp2[RS_EPSZ];

		//sample t (commit secret)
		crypto_core_ristretto255_scalar_random(t1);
		crypto_core_ristretto255_scalar_random(t2);
		//sample c (challenge)
		crypto_core_ristretto255_scalar_random(c);

		//compute response
		crypto_core_ristretto255_scalar_mul( y , c, usk->s1 );
		crypto_core_ristretto255_scalar_add( y, y, t1 );
		crypto_core_ristretto255_scalar_mul( y+RS_SCSZ , c, usk->s2 );
		crypto_core_ristretto255_scalar_add( y+RS_SCSZ, y+RS_SCSZ, t2 );

		xp = hashexec(mbuffer, mlen, usk->U, par->P);

		//T = tB
		rc = 0;
		rc += crypto_scalarmult_ristretto255_base( tmp1, t1);
		rc += crypto_scalarmult_ristretto255( tmp2, t2, usk->B2);
		rc += crypto_core_ristretto255_add( tmp, tmp1, tmp2);

		rc += crypto_scalarmult_ristretto255_base( LHS, y);
		rc += crypto_scalarmult_ristretto255( tmp1, y+RS_SCSZ, par->B2);
		rc += crypto_core_ristretto255_add( LHS, LHS, tmp1); // z1g1 z2g2

		rc += crypto_scalarmult_ristretto255( tmp1, xp, par->P); // xP
		rc += crypto_core_ristretto255_sub( tmp1, usk->U, tmp1); // U' - xP
		rc += crypto_scalarmult_ristretto255( tmp1, c, tmp1); // c( U' - xP )
		rc += crypto_core_ristretto255_add( RHS, tmp1, tmp); // T + c(U' - xP)
		if( rc != 0 ) return rc; //abort if fail

		//check LHS == RHS
		rc = crypto_verify_32( LHS, RHS );

		hashfree(xp);

		return rc;
	}

}
