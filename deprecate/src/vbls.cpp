/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/
Last edit : 01 Jan 2020  -- ToraNova2019

The MIT License (MIT)

Copyright (c) 2019 Chia Jason

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// declaration includes
#include "vbls.hpp"
#include "ptdebug.h"

//mini socket library
#include "simplesock.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// implementation includes
#include <pbc/pbc.h> //for the pairing based crypto magic
#include <gmp.h> //gnu multiprecision

// standard lib
#include <cstdlib>
#include <cstdio>
#include <time.h>

using namespace std;
namespace vbls
{
	namespace ss{

	int keygen(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//vars
		pairing_t pairing;
		element_t a, b;
		element_t g1, g2;
		element_t x1, x2, y;
		size_t n; int rc; //n used for size storage and rc for result code
		size_t ntmp;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}


		//initialize the public params
		element_init_G1(g1, pairing);
		element_init_G1(x1, pairing);
		element_init_G1(x2, pairing);
		element_init_G2(g2, pairing);
		element_init_G2(y, pairing);
		element_init_Zr(a, pairing);
		element_init_Zr(b, pairing);

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		//generates secret key and public key
		element_random(a);
		element_random(b);
		element_random(g1);
		element_random(g2);
		element_pow_zn( x1, g1, a);
		element_pow_zn( x2, g1, b);
		element_pow_zn( y, g2, a);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		debug("t: %f ms", cpu_time_used );

		//calculate the amount of memory required for public and secret key, then allocate
		ntmp = pairing_length_in_bytes_compressed_G2(pairing);
		debug("G2 sz: %lu",ntmp);

		n = pairing_length_in_bytes_compressed_G1(pairing); //(compressed)
		debug("G1 sz: %lu",n);

		n = n + 2*ntmp; //mpk <- g2, x2, y
		*pbuffer = (unsigned char *)malloc( n );
		*plen = n;
		debug("Pk sz: %lu",*plen);

		n = pairing_length_in_bytes_Zr(pairing); //one pubkey
		debug("Zr sz: %lu",n);
		*sbuffer = (unsigned char *)malloc( n );
		*slen = n; //msk <- a
		debug("Sk sz: %lu",*slen);

		element_to_bytes_compressed( *pbuffer, g2 ); //write g2 first
		element_to_bytes_compressed( *pbuffer+ntmp, y ); //then y
		element_to_bytes_compressed( *pbuffer+2*ntmp, x2 ); //then x2 (G1)
		element_to_bytes( *sbuffer, a );

		//cleanup
		element_clear(g1);
		element_clear(g2);
		element_clear(x2);
		element_clear(x1);
		element_clear(y);
		element_clear(a);
		element_clear(b);
		pairing_clear(pairing);
		return 0;
	}

	int sign(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		//vars
		int rc; size_t n;
		pairing_t pairing;
		element_t a, r, h, sig, x2, tmp;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//sample a random bit by reading a long from urandom and modulo 2
		FILE *urandom_fd = fopen("/dev/urandom", "r");
		if(urandom_fd == NULL){
			log_err("Error opening /dev/urandom");
			return 1;
		}

		//initialize the public/secret params
		element_init_G1(x2, pairing);
		element_init_G1(tmp, pairing);

		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_Zr(a, pairing);
		element_init_Zr(r, pairing);

		n = pairing_length_in_bytes_compressed_G2(pairing);

		//compressed
		element_from_bytes_compressed( x2, pbuffer+2*n ); //skip the two G2 element (g2,y)

		//secret parsing (this is stable)
		element_from_bytes( a, sbuffer );

		//sample a long from urandom, and obtain a bit from it
		signed long int urandbuf;
		fread( &urandbuf, sizeof(signed long int), 1, urandom_fd ); //read one long into
		if(urandbuf < 0) urandbuf = -urandbuf;
		urandbuf = urandbuf % 2;
		debug("urand: %li", urandbuf );
		element_set_si( r, urandbuf );
		fclose(urandom_fd);

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		//compute element from hash
		element_from_hash(h, mbuffer, mlen);

		element_pow_zn( tmp, x2, r );
		element_mul( tmp, h, tmp );

		//compute signature (b is only used for proof)
		element_pow_zn(sig, tmp, a);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		debug("t: %f ms", cpu_time_used );

		n = pairing_length_in_bytes_compressed_G1(pairing);
		debug("G1 sz: %lu",n);
		*olen = 2*n+1; //+1 for rbit
		*obuffer = (unsigned char *)malloc( *olen );
		debug("Out sz: %lu",*olen);
		debug("M sz: %lu",mlen);

		//store x element of signature
		element_to_bytes_compressed( *obuffer, sig );

		// 29 December 2019 (append the x2 as well)
		(*obuffer)[n] = (unsigned char) (urandbuf & 0x1); //only the LSB
		debug("PRB: %d @ pos %lu", (*obuffer)[n], n);
		element_to_bytes_compressed( *obuffer+(n+1), x2 );
		debug("Appended X2 at position %lu",n+1);

		//cleanup
		element_clear(x2);
		element_clear(tmp);
		element_clear(a);
		element_clear(r);
		element_clear(sig);
		element_clear(h);

		pairing_clear(pairing);
		return 0;
	}

	int verify(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		//vars
		signed long int urandbuf;
		int rc; int out; size_t n;
		pairing_t pairing;
		element_t r, h, sig;
		element_t g2;
		element_t x2, y;
		element_t temp1, temp2;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the public/secret params
		element_init_G2(g2, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_G2(y, pairing);
		element_init_Zr(r, pairing);

		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);

		//parsing g2,y x2
		n = pairing_length_in_bytes_compressed_G2(pairing);
		element_from_bytes_compressed( g2, pbuffer );
		element_from_bytes_compressed( y, pbuffer+n );
		element_from_bytes_compressed( x2, pbuffer+2*n );

		//parsing sig
		element_from_bytes_compressed( sig, obuffer );
		debug("OLN: %lu",olen);

		//setting randbit
		n = pairing_length_in_bytes_compressed_G1(pairing);
		urandbuf = obuffer[n];
		debug("PRB: %li @ pos %lu HEX: %02X", urandbuf, n, obuffer[n]);
		element_set_si( r, urandbuf);

		//compute element from hash
		element_from_hash(h, mbuffer, mlen);
		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 );
		element_pairing( temp1, x2, y );
		element_pairing( temp2, sig, g2);

		if( !element_cmp(temp1, temp2) ){
			//first attemp valid
			verbose("Valid Signature on attempt 1.");
			out = 0;
		} else {
			//try second attempt
			element_invert(temp1, temp1); //invert for the other point
			if (!element_cmp(temp1, temp2)) {
				verbose("Valid Signature on attempt 2.");
				out = 0;
			} else {
				verbose("Invalid Signature.");
				out = 1;
			}

		}

		//cleanup
		element_clear(g2);
		element_clear(x2);
		element_clear(y);
		element_clear(r);
		element_clear(sig);
		element_clear(h);
		element_clear(temp1);
		element_clear(temp2);
		pairing_clear(pairing);

		//return result
		return out;
	}

	}

	namespace ibi{

	/*
	 * Setup and Extract are trivial to code, they follow same structure
	 * as the Keygen and Sign of the original BLS signature scheme
	 */
	int setup(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//setup for ibi system is the keygen for msk and usk
		//pubstream is msk while usk is secret_stream
		return ss::keygen( paramstr, pstrlen, pbuffer, plen, sbuffer, slen);
	}

	int extract(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		//extract is using the msk to sign on an id, resulting in a usk
		return ss::sign( paramstr, pstrlen, pbuffer, plen, sbuffer, slen, mbuffer, mlen, obuffer, olen);
	}

	int prove(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int port, const char *srv,
		int timeout
	){

		//vars
		signed long int urandbuf;
		unsigned char *test;
		int rc; size_t n, i;
		pairing_t pairing;
		element_t r, t, h, usk;
		//element_t g2, y;
		element_t x2;
		element_t CMT,CHA,RSP; //random element and the challenge
		char buf[CONN_MAXBF_SIZE] = {0};
		short tsock;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize elements
		//element_init_G2(g2, pairing);
		//element_init_G2(y, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_G1(usk, pairing);
		element_init_Zr(r, pairing);
		element_init_Zr(t, pairing);
		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		//parse and set element values
		//n = pairing_length_in_bytes_compressed_G2(pairing);
		//element_from_bytes_compressed( x2, pbuffer+2*n );

		//element_from_bytes_compressed( g2, pbuffer );
		//element_from_bytes_compressed( y, pbuffer+n );

		n = pairing_length_in_bytes_compressed_G1(pairing);
		element_from_bytes_compressed( usk, obuffer );
		element_from_bytes_compressed( x2, obuffer+n+1 );

#ifdef EDEBUG
		test = (unsigned char *)malloc(n);
		element_to_bytes_compressed( test, usk );
		printf("usk hextest %lu:\n",n);
		for(i=0;i< n;i++){
			printf("%02x", test[i]);
		}
		printf("\n");

		memset( test, 0, n);
		element_to_bytes_compressed( test, x2 );
		printf("x2 hextest %lu:\n",n);
		for(i=0;i< n;i++){
			printf("%02x", test[i]);
		}
		printf("\n");
		free(test);
#endif


		urandbuf = obuffer[n];
		debug("PRB: %li @ pos %lu HEX: %02X", urandbuf, n, obuffer[n]);
		element_set_si( r, urandbuf);

		//Create socket
		tsock = sockgen(0);
		if(tsock == -1){log_err("Socket creation failed");return 1;}

		//Attempt to connect
		verbose("Attempting to connect to %s:%d",srv,port);
		if( sockconn(tsock, srv, port) < 0){log_err("Failed to connect to verifier");return 1;}
		verbose("Connection established with %s:%d",srv,port);
		verbose("Sending ID string %s",mbuffer);
		sendbuf(tsock, (char *)mbuffer , mlen, timeout);
		//await byte 0x5a before proceeding with protocol
		if( recv(tsock, buf, 1, 0) < 0 || buf[0] != 0x5a){
			log_err("Failed to recv go-ahead (0x5a) byte");
			return 1;
		}
		verbose("Go-Ahead received (0x5a), Starting PROVE protocol");

		//--------------COMPUTE COMMIT

		/*
		unsigned char fixedT[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
		element_from_bytes( t, fixedT );
		*/
		element_random(t); //P samples a random r and performs scalar mutliply with hash of ID

		//compute element from hash
		element_from_hash(h, mbuffer, mlen);

		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 ); //compute H(id) * x2^-r
		//performs scalar multiply (raise to power)
		element_pow_zn( CMT, x2, t); // CMT = (H(id) * x2^-r) ^t , r


		//--------------SEND COMMIT PHASE
		memset(buf,'\0', CONN_MAXBF_SIZE); //reset
		element_to_bytes_compressed( (unsigned char *)buf, CMT ); //store the x element only

		//include the random bit
		buf[n] = obuffer[n];
		sendbuf(tsock, buf , n+1, timeout);

		verbose("Commit Sent %lu",n+1);

		//--------------RECEIVE CHALLENGE
		memset(buf,'\0', CONN_MAXBF_SIZE);
		rc = recv(tsock, buf, CONN_MAXBF_SIZE, 0);
		if( rc < 0 ){
			log_err("Failed to recv CHALLENGE from verifier");
			return 1;
		}
		element_from_bytes( CHA, (unsigned char *) buf );

		test = (unsigned char *)malloc( CONN_MAXBF_SIZE );
		element_snprintf( (char *)test, CONN_MAXBF_SIZE, "Received Challenge :\n%B", CHA);
		verbose("%s",(char *)test);
		free(test);

		//----------------COMPUTE RESPONSE
		element_add( t, t, CHA); //compute t+CHA
		element_pow_zn( RSP, usk, t); // RSP = usk^(r+CHA)

		verbose("Computing Response...");

		//----------------SEND RESPONSE
		n = pairing_length_in_bytes_compressed_G1(pairing);
		memset(buf,'\0', CONN_MAXBF_SIZE); //reset
		element_to_bytes_compressed( (unsigned char *)buf, RSP ); //store the x element only
		sendbuf(tsock, buf , n, timeout);

		verbose("Reponse Sent %lu",n);
#ifdef EDEBUG
		element_printf("SEND CMT: %B\n", CMT);
		element_printf("SEND RBIT: %B\n", r);
		element_printf("RECV CHA: %B\n", CHA);
		element_printf("SEND RSP: %B\n", RSP);
#endif

		rc = recv(tsock, buf, 1, 0); //receive final result
		if( rc < 0 ){
			log_err("Failed to recv RESULT from verifier");
			return 1;
		}

		//close socket
		close(tsock);

		//cleanup
		//element_clear(g2);
		//element_clear(y);
		element_clear(x2);
		element_clear(h);
		element_clear(t);
		element_clear(r);
		element_clear(CMT);
		element_clear(CHA);
		element_clear(RSP);
		pairing_clear(pairing);

		//return OK
		return (int) buf[0];
	}

	int verify(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	){

		//vars
		int rc, out; size_t n;
		pairing_t pairing;
		element_t r, h;
		element_t g2;
		element_t x2, y;
		element_t temp1, temp2;
		element_t CMT,CHA,RSP; //random element and the challenge

		unsigned char *test;
		struct sockaddr_in cli;
		short ssock,csock; //server socket and client socket
		int cli_len = sizeof(struct sockaddr_in);
		char buf[CONN_MAXBF_SIZE] = {0};
		char ackp[1] = { CONN_ACK };

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		element_init_G2(g2, pairing);
		element_init_G2(y, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_Zr(r, pairing);
		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);
		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		//parse and set element values
		n = pairing_length_in_bytes_compressed_G2(pairing);
		element_from_bytes_compressed( g2, pbuffer );
		element_from_bytes_compressed( y, pbuffer+n );
		element_from_bytes_compressed( x2, pbuffer+2*n );

#ifdef EDEBUG
		n = pairing_length_in_bytes_compressed_G1(pairing);
		size_t i;
		test = (unsigned char *)malloc(n);
		element_to_bytes_compressed( test, x2 );
		printf("x2 hextest %lu:\n",n);
		for(i=0;i< n;i++){
			printf("%02x", test[i]);
		}
		printf("\n");
#endif

		//Create socket
		ssock = sockgen(0);
		if(ssock == -1){log_err("Socket creation failed");return 1;}
		//bind the socket
		if(sockbind(ssock,port, 1) < 0){log_err("Port bind failed");return 1;}

		//listen for incoming conn
		verbose("Listening for verification attempts on port %d",port);
		listen(ssock, 1);

		//CLOCK TIMING
		clock_t start, end;
		double cpu_time_used;
		start = clock();
		//CLOCK TIMING

		csock = accept( ssock, (struct sockaddr *)&cli, (socklen_t*)&cli_len);
		if(csock < 0){log_err("Connection failed to establish");return 1;}
		verbose("Connection established");
		rc = recv(csock, buf, CONN_MAXBF_SIZE, 0);
		if( rc < 0 ){
			log_err("Failed to recv ID string from prover");
			return 1;
		}
		*mlen = (size_t)rc;
		*mbuffer = (unsigned char *)malloc(*mlen);
		memcpy( *mbuffer, buf, *mlen );
		verbose("ID string %s (%lu)",*mbuffer,*mlen);
		//echo back ox5a to begin protocol
		if( send(csock, ackp, 1, 0) < 0){log_err("Failed to echo back go-ahead (0x5a)");}
		verbose("Go-Ahead sent (0x5a), Starting VERIFY protocol");

		//----------------------RECEIVE COMMIT
		memset(buf,'\0', CONN_MAXBF_SIZE);
		n = pairing_length_in_bytes_compressed_G1(pairing);
		rc = recv(csock, buf, CONN_MAXBF_SIZE, 0);
		if( rc < 0 ){
			log_err("Failed to recv COMMIT from prover");
			return 1;
		}
		verbose("Commit Received");

		//read last bit first
		signed long int urandbuf = buf[n];
		element_set_si( r, urandbuf);
		buf[n] = 0x00; //reset it
		element_from_bytes_compressed( CMT, (unsigned char *) buf );

		//---------------------SEND THE CHALLENGE

		/*
		unsigned char fixedT[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
		element_from_bytes(CHA, fixedT );
		*/
		element_random(CHA);

		test = (unsigned char *)malloc( CONN_MAXBF_SIZE );
		element_snprintf( (char *)test, CONN_MAXBF_SIZE, "Send Challenge :\n%B", CHA);
		verbose("%s",(char *)test);
		free(test);

		n = pairing_length_in_bytes_Zr(pairing);
		memset(buf,'\0', CONN_MAXBF_SIZE); //reset
		element_to_bytes( (unsigned char *)buf, CHA ); //store the x element only
		sendbuf(csock, buf , n, timeout);

		//---------------------RECEIVE RESPONSE
		memset(buf,'\0', CONN_MAXBF_SIZE);
		n = pairing_length_in_bytes_G1(pairing);
		rc = recv(csock, buf, CONN_MAXBF_SIZE, 0);
		if( rc < 0 ){
			log_err("Failed to recv RESPONSE from prover");
			return 1;
		}
		element_from_bytes_compressed( RSP, (unsigned char *) buf );

		verbose("Received Response...Computing Validity");

#ifdef EDEBUG
		element_printf("RECV CMT: %B\n", CMT);
		element_printf("RECV RBIT: %B\n", r);
		element_printf("SEND CHA: %B\n", CHA);
		element_printf("RECV RSP: %B\n", RSP);
		printf("RECV MBUF %lu:",*mlen);
		for(i=0;i<*mlen;i++){
			printf("%02x",(*mbuffer)[i]);
		}
		printf("\n");
#endif


		//-----------------------COMPUTE VALIDITY
		element_from_hash(h, *mbuffer, *mlen);
		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 ); //compute H(id) * x2^-r
		element_pow_zn( x2, x2, CHA );
		element_mul( x2, CMT, x2 );
		element_pairing(temp1, x2, y);
		element_pairing(temp2, RSP, g2);

#ifdef EDEBUG
		element_printf("COMP H: %B\n", h);
		element_printf("COMP T1: %B\n",temp1);
		element_printf("COMP T2: %B\n",temp2);
#endif

		//refer https://crypto.stanford.edu/pbc/manual/ch02s02.html
		//since there is high possibility of guessing wrong
		//2 compressed G1, thus we assume we guessed wrong
		//and only invert back when it doesn't validate
		//element_invert(temp1, temp1);
		if( !element_cmp(temp1, temp2) ){
			//first attemp valid
			debug("Valid Verification on attempt 1.");
			out = 0;
			buf[0] = 0x00;
		} else {
			//try second attempt (assume CHA inverted)
			element_invert(temp1, temp1); //invert for the other point
			if (!element_cmp(temp1, temp2)) {
				debug("Valid Verfication on attempt 2.");
				out = 0;
				buf[0] = 0x00;
			} else {
				debug("Verification Test Failed.");
				out = 1;
				buf[0] = 0x01;
			}
		}

		sendbuf(csock, buf , 1, timeout); //send back the results

		//close the client socket conn
		close(csock);
		close(ssock);

		//CLOCK TIMING
		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		log_info("t: %f ms", cpu_time_used );
		//CLOCK TIMING

		//cleanup
		element_clear(g2);
		element_clear(x2);
		element_clear(y);
		element_clear(h);
		element_clear(temp1);
		element_clear(temp2);
		element_clear(r);
		element_clear(CMT);
		element_clear(CHA);
		element_clear(RSP);
		pairing_clear(pairing);

		//return result
		return out;
	}

	/*
	 * Here is the challenge, we need to code the actual HVZKP into this
	 * to simulate a true prover/verifier run
	 * NOTE THAT THIS IS A TEST, NOT THE ACTUAL PROVE/VERIFY ALGO
	 * BECAUSE THEY ARE RAN ON THE SAME MACHINE!
	 */
	int verifytest(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		//vars
		int rc, out; size_t n;
		pairing_t pairing;
		element_t r, t, h, usk;
		element_t g2;
		element_t x2, y;
		element_t temp1, temp2;
		element_t CMT,CHA,RSP; //random element and the challenge

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the public/secret params
		element_init_G2(g2, pairing);
		element_init_G2(y, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_G1(usk, pairing);
		element_init_Zr(r, pairing);

		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);
		element_init_Zr(t, pairing);

		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		n = pairing_length_in_bytes_compressed_G2(pairing);

		//compressed
		element_from_bytes_compressed( g2, pbuffer );
		element_from_bytes_compressed( y, pbuffer+n );
		element_from_bytes_compressed( x2, pbuffer+2*n );
		element_from_bytes_compressed( usk, obuffer );

		n = pairing_length_in_bytes_compressed_G1(pairing);
		signed long int urandbuf = obuffer[n];
		element_set_si( r, urandbuf);

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		// ----- BEGIN TEST -----

		// FIRST PASS
		element_random(t); //P samples a random r and performs scalar mutliply with hash of ID
		//compute element from hash
		element_from_hash(h, mbuffer, mlen);
		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 ); //compute H(id) * x2^-r

		//performs scalar multiply (raise to power)
		element_pow_zn( CMT, x2, t); // CMT = (H(id) * x2^-r) ^t , r
		// CMT is sent to V

		// SECOND PASS
		// V samples a challenge and sends it to P
		element_random(CHA);

		// THIRD PASS
		// P computes the RSP
		element_add( t, t, CHA); //compute t+CHA
		element_pow_zn( RSP, usk, t); // RSP = usk^(r+CHA)
		// RSP is sent back to V

		// V test
		// compute H(ID)^(r+CHA)
		element_pow_zn( x2, x2, CHA );
		element_mul( x2, CMT, x2 );

		element_pairing(temp1, x2, y);
		element_pairing(temp2, RSP, g2);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		debug("t: %f ms", cpu_time_used );

		if( !element_cmp(temp1, temp2) ){
			//first attemp valid
			debug("Valid Verification on attempt 1.");
			out = 0;
		} else {
			//try second attempt
			element_invert(temp1, temp1); //invert for the other point
			if (!element_cmp(temp1, temp2)) {
				debug("Valid Verfication on attempt 2.");
				out = 0;
			} else {
				debug("Verification Test Failed.");
				out = 1;
			}

		}

		//cleanup
		element_clear(g2);
		element_clear(x2);
		element_clear(y);
		element_clear(usk);
		element_clear(h);
		element_clear(t);
		element_clear(temp1);
		element_clear(temp2);
		element_clear(r);
		element_clear(CMT);
		element_clear(CHA);
		element_clear(RSP);
		pairing_clear(pairing);

		//return result
		return out;
	}



	}
}
