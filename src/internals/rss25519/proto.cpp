/*
 * internals/rss25519/proto.cpp - id2 library
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
 * Schnorr IBI protocols
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

namespace rss25519{

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
		unsigned char t[2*RS_SCSZ], c[RS_SCSZ], y[RS_SCSZ];
		unsigned char *xp;
		unsigned char tmp1[RS_EPSZ], tmp2[RS_EPSZ], tmp[RS_SCSZ];
		unsigned char buf[TS_MAXSZ] = {0};

		//--------------------------------------------------------
		//--------------RECEIVE PRE-NONCE
		rc = fixed_recvbuf(sock, (char *)c, RS_EPSZ);
		if( rc <= 0 ){
			lerror("Failed to recv PRE-NONCE from prover\n");
			return 1;
		}

		//COMPUTE NONCE WITH PRE-NONCE AS SEED
		randombytes_buf(y, RS_EPSZ);
		xp = hashexec( mbuffer, mlen, y, c);

		//--------------------------------------------------------
		//--------------COMPUTE AND SEND COMMIT
		//CMT <- U', T
		// T = tB
		memcpy( buf, usk->U, RS_EPSZ);
		rc = crypto_scalarmult_ristretto255_base( buf+RS_EPSZ, xp);
		if( rc != 0 ){
			//abort if fail
			lerror("Failed to compute COMMIT\n");
			return 1;
		}
		sendbuf( sock, (char *)buf , 2*RS_EPSZ); //send CMT

		//--------------------------------------------------------
		//--------------RECEIVE REVEAL
		rc = fixed_recvbuf(sock, (char *)t, 2*RS_SCSZ);
		if( rc <= 0 ){
			lerror("Failed to recv REVEAL from verifier\n");
			return 1;
		}

		//--------------------------------------------------------
		//--------------VERIFY REVEAL
		rc = 0;
		rc += crypto_scalarmult_ristretto255_base( tmp1, t); //fixed
		rc += crypto_scalarmult_ristretto255( tmp2, t+RS_SCSZ, usk->P2);//rH
		rc += crypto_core_ristretto255_add( tmp, tmp1, tmp2);
		rc += crypto_verify_32(tmp, c);
		if( rc != 0){
			//prevent reset attacks by aborting
			lerror("Invalid REVEAL, aborting\n");
#ifdef DEBUG
	sigprint(usk);
	printf("C1:"); ucbprint(tmp1, RS_SCSZ); printf("\n");
	printf("C2:"); ucbprint(tmp2, RS_SCSZ); printf("\n");
	printf("c :"); ucbprint(c, RS_SCSZ); printf("\n");
	printf("c':"); ucbprint(tmp, RS_SCSZ); printf("\n");
#endif
			//send back garbage
			sendbuf(sock, (char *)y , RS_SCSZ);
			return 1;
		}

		//--------------COMPUTE AND SEND RESPONSE
		// y = t + cs
		crypto_core_ristretto255_scalar_mul( y, c, usk->s ); //
		crypto_core_ristretto255_scalar_add( y, y, xp );

#ifdef DEBUG
	sigprint(usk);
	printf("t :"); ucbprint(xp, RS_SCSZ); printf("\n");
	printf("T :"); ucbprint(buf+RS_EPSZ, RS_EPSZ); printf("\n");
	printf("C1:"); ucbprint(tmp1, RS_SCSZ); printf("\n");
	printf("C2:"); ucbprint(tmp2, RS_SCSZ); printf("\n");
	printf("c :"); ucbprint(c, RS_SCSZ); printf("\n");
	printf("y :"); ucbprint(y, RS_SCSZ); printf("\n");
#endif

		hashfree(xp);
		sendbuf(sock, (char *)y , RS_SCSZ);

		buf[0] = 0x01;
		rc = fixed_recvbuf(sock, (char *)buf, 1); //receive final result
		if( rc <= 0 ){
			lerror("Failed to recv RESULT from verifier\n");
			return 1;
		}
		debug("Received: %02X\n",buf[0]);
		//--------------------------TODO END

		return (int)buf[0];
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
		unsigned char pc[2*RS_SCSZ];
		unsigned char c[RS_SCSZ], y[RS_SCSZ], *xp;
		unsigned char LHS[RS_EPSZ], RHS[RS_EPSZ];
		unsigned char buf[TS_MAXSZ] = {0};

		//--------------------------------------------------------
		//--------------COMPUTE AND SEND PRE-NONCE
		crypto_core_ristretto255_scalar_random(pc); //m
		crypto_core_ristretto255_scalar_random(pc+RS_SCSZ); //r
		rc = 0;
		rc += crypto_scalarmult_ristretto255_base( LHS, pc);//mB
		rc += crypto_scalarmult_ristretto255( RHS, pc+RS_SCSZ, par->P2 );//rH
		rc += crypto_core_ristretto255_add( c, LHS, RHS ); //compute pre-nonce
		if( rc != 0 ) return rc; //abort if fail
		sendbuf(sock, (char *)c , RS_SCSZ);

		//--------------------------------------------------------
		//--------------RECEIVE COMMIT FROM PROVER
		//CMT <- U, T
		rc = fixed_recvbuf(sock, (char *)buf, 2*RS_EPSZ);
		if( rc <= 0 ){
			lerror("Failed to recv COMMIT from prover\n");
			return 1;
		}

		//--------------------------------------------------------
		//---------------------REVEAL THE PRE-NONCE
		sendbuf(sock, (char *)pc , 2*RS_SCSZ);
		memset(y, 0, RS_SCSZ);

		//--------------------------------------------------------
		//---------------------RECEIVE RESPONSE
		rc = fixed_recvbuf(sock, (char *)y, RS_SCSZ);
		if( rc <= 0 ){
			lerror("Failed to recv RESPONSE from prover\n");
			return 1;
		}

		//hash
		xp = hashexec(mbuffer, mlen, buf, par->P1);

#ifdef DEBUG
	pubprint(par);
	printf("U :"); ucbprint( buf, RS_EPSZ ); printf("\n");
	printf("T :"); ucbprint( buf+RS_EPSZ, RS_EPSZ ); printf("\n");
	printf("C1:"); ucbprint( LHS, RS_SCSZ ); printf("\n");
	printf("C2:"); ucbprint( RHS, RS_SCSZ ); printf("\n");
	printf("c :"); ucbprint( c, RS_SCSZ ); printf("\n");
	printf("y :"); ucbprint( y, RS_SCSZ ); printf("\n");
	printf("x':"); ucbprint( xp, RS_SCSZ ); printf("\n");
#endif

		// yB = T + c( U' - xP1 )
		rc = 0;
		rc += crypto_scalarmult_ristretto255( RHS, xp, par->P1); // xP1
		//zero and free
		hashfree(xp);
		rc += crypto_scalarmult_ristretto255_base( LHS, y); // yB
		rc += crypto_core_ristretto255_sub( RHS, buf, RHS); // U' - xP1
		rc += crypto_scalarmult_ristretto255( RHS, c, RHS); // c( U' - xP1 )
		// T + c(U' - xP1)
		rc += crypto_core_ristretto255_add( RHS, RHS, buf+RS_EPSZ);
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

	//TODO: implement this routine
	int prototest(
		void *vpar,
		void *vusk,
		const unsigned char *mbuffer, size_t mlen
	){
		//key recast
		struct pubkey *par = (struct pubkey *)vpar;
		struct signat *usk = (struct signat *)vusk;
		int rc;

		//------------------------------------TODO START
		unsigned char t[2*RS_SCSZ], c[RS_SCSZ], y[RS_SCSZ], *xp;
		unsigned char tmp[RS_EPSZ], LHS[RS_EPSZ], RHS[RS_EPSZ];

		//sample the pre-nonces
		crypto_core_ristretto255_scalar_random(t);
		crypto_core_ristretto255_scalar_random(t+RS_SCSZ);

		//compute challenge from pre-nonce
		rc = 0;
		rc += crypto_scalarmult_ristretto255_base( LHS, t);//mB
		rc += crypto_scalarmult_ristretto255( RHS, t+RS_SCSZ, par->P2 );//rH
		rc += crypto_core_ristretto255_add( c, LHS, RHS ); //compute pre-nonce

		//compute nonce from challenge
		randombytes_buf(y, RS_EPSZ);
		xp = hashexec( mbuffer, mlen, y, c); //xp is the nonce
		rc += crypto_scalarmult_ristretto255_base( tmp, xp); //stores Y

		//c == tB (t+SCSZ)P1 no need to check
		//compute response
		crypto_core_ristretto255_scalar_mul( y , c, usk->s ); //
		crypto_core_ristretto255_scalar_add( y, y, xp ); // y = t + cs
		hashfree(xp);

		xp = hashexec(mbuffer, mlen, usk->U, par->P1);

		// yB = T + c( U' - xP1 )
		rc += crypto_scalarmult_ristretto255( RHS, xp, par->P1); // xP1
		//zero and free
		hashfree(xp);
		rc += crypto_scalarmult_ristretto255_base( LHS, y); // yB
		rc += crypto_core_ristretto255_sub( RHS, usk->U, RHS); // U' - xP1
		rc += crypto_scalarmult_ristretto255( RHS, c, RHS); // c( U' - xP1 )
		// T + c(U' - xP1)
		rc += crypto_core_ristretto255_add( RHS, RHS, tmp);
		if( rc != 0 ) return rc; //abort if fail

		//check LHS == RHS
		rc = crypto_verify_32( LHS, RHS );
		debug("rc=%d\n",rc);
		//------------------------------------TODO END

		return rc;
	}

}
