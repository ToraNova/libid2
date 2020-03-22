/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/

!! NOTE !!
THIS IS THE OPTIMIZED VERSION
REMOVED KEY OR WRITES THAT ARE NOT USED
THIS CANNOT WORK WELL WITH NON OPTIMIZED
AS SOME ELEMENTS ARE NOT WRITTEN AT ALL

ToraNova2019
*/

// declaration includes
#include "bls_tight.hpp"
#include "ptdebug.h"

// custom parsing functions
#include "futil.hpp"

// implementation includes
#include <pbc/pbc.h> //for the pairing based crypto magic
#include <gmp.h> //gnu multiprecision

// standard lib
#include <string>
#include <cstdlib>
#include <cstdio>

using namespace std;
namespace bls_tight
{
	namespace opti{

	void keygen(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream
	){
		//vars
		pairing_t pairing;
		element_t a, b;
		element_t g1, g2;
		element_t x1, x2, y;
		unsigned int i; //used as counter later
		size_t n; int rc; //n used for size storage and rc for result code
		unsigned char *outbuf;

		//allocate for output buffer
		//TODO: implement element_to_bytes and element_from_bytes

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return; }
		}

		//initialize the public params
		element_init_G1(g1, pairing);
		element_init_G1(x1, pairing);
		element_init_G1(x2, pairing);
		element_init_G2(g2, pairing);
		element_init_G2(y, pairing);
		element_init_Zr(a, pairing);
		element_init_Zr(b, pairing);

		//generates secret key and public key
		element_random(a);
		element_random(b);
		element_random(g1);
		element_random(g2);
		element_pow_zn( x1, g1, a);
		element_pow_zn( x2, g1, b);
		element_pow_zn( y, g2, a);

		//msk <- a,b
		//mpk <- g1,g2,x1,x2,y

		// TODO: use utility function to do the below
		debug("Outputting public element");
		//FOR G (SYSTEM PARAM)
		//obtain length to allocate later
		//n = pairing_length_in_bytes_x_only_G2(pairing);
		n = pairing_length_in_bytes_compressed_G2(pairing); //(compressed)
		//n = pairing_length_in_bytes_G2(pairing);
		outbuf = (unsigned char *)malloc( sizeof(unsigned char)* n); //allocate buffer
		//the above buffer can be cleared using pbc_free
		debug("G2 sz:%lu",n);

		// WRITING g2
		element_to_bytes_compressed( outbuf, g2 ); //compressed
		fprintf(public_stream, "{\"g2\": \""); //prepare to write sys params
		for(i=0;i<n;i++){
			fprintf(public_stream, "%02X", outbuf[i]);
		}
		fprintf(public_stream, "\","); //seperator (json style)
		//--------------------------------------------------------------
		memset( outbuf, 0, n); //reset the memory
		//WRITING y
		element_to_bytes_compressed( outbuf, y ); //store the x element only
		fprintf(public_stream, "\"y\": \""); //prepare to write pub key
		for(i=0;i<n;i++){
			fprintf(public_stream, "%02X", outbuf[i]);
		}
		fprintf(public_stream, "\","); //seperator (json style)
		//--------------------------------------------------------------

		free(outbuf); //free the buffer for reallocation later

		n = pairing_length_in_bytes_compressed_G1(pairing); //(compressed)
		outbuf = (unsigned char *)malloc( sizeof(unsigned char)* n); //allocate buffer
		debug("G1 sz:%lu",n);

		//WRITING g1
		/*
		element_to_bytes_compressed( outbuf, g1 ); //compressed
		fprintf(public_stream, "\"g1\": \""); //prepare to write pub key
		for(i=0;i<n;i++){
			fprintf(public_stream, "%02X", outbuf[i]);
		}
		fprintf(public_stream, "\","); //seperator (json style)
		memset( outbuf, 0, n); //reset the memory

		//WRITING x1
		element_to_bytes_compressed( outbuf, x1 ); //compressed
		fprintf(public_stream, "\"x1\": \""); //prepare to write pub key
		for(i=0;i<n;i++){
			fprintf(public_stream, "%02X", outbuf[i]);
		}
		fprintf(public_stream, "\","); //seperator (json style)
		memset( outbuf, 0, n); //reset the memory
		*/

		//WRITING x2
		element_to_bytes_compressed( outbuf, x2 ); //compressed
		fprintf(public_stream, "\"x2\": \""); //prepare to write pub key
		for(i=0;i<n;i++){
			fprintf(public_stream, "%02X", outbuf[i]);
		}
		fprintf( public_stream, "\"}\n");
		free(outbuf); //free the buffer for reallocation later

		//FOR SECRET COMPONENT OF KEY
		debug("Outputting private element");
		//obtain length to allocate later (FOR Zr now)
		n = pairing_length_in_bytes_Zr(pairing);
		outbuf = (unsigned char *)malloc( sizeof(unsigned char)* n); //allocate buffer
		debug("Zr sz:%lu",n);

		//WRITING a
		element_to_bytes( outbuf, a ); //store the x element only
		fprintf(secret_stream,"{\"a\": \"");
		for(i=0;i<n;i++){
			fprintf(secret_stream, "%02X", outbuf[i]);
		}
		memset( outbuf, 0, n); //reset the memory

		fprintf( secret_stream, "\"}\n");

		/*
		fprintf(secret_stream, "\","); //seperator (json style)

		//WRITING b
		element_to_bytes( outbuf, b ); //store the x element only
		fprintf(secret_stream,"\"b\": \"");
		for(i=0;i<n;i++){
			fprintf(secret_stream, "%02X", outbuf[i]);
		}
		fprintf( secret_stream, "\"}\n");
		*/
		free(outbuf); //free the memory

		//cleanup
		element_clear(g1);
		element_clear(g2);
		element_clear(x2);
		element_clear(x1);
		element_clear(y);
		element_clear(a);
		element_clear(b);
		pairing_clear(pairing);
		return;
	}

	void sign(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *message_stream, FILE *sign_stream
	){
		//vars
		int rc; unsigned int i;
		pairing_t pairing;
		element_t a, r, h, sig, x2;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return; }
		}

		//sample a random bit by reading a long from urandom and modulo 2
		FILE *urandom_fd = fopen("/dev/urandom", "r");
		if(urandom_fd == NULL){
			log_err("Error opening /dev/urandom");
			return;
		}

		char *msgbuf; long fsize; //message buffer
		unsigned char *outbuf; size_t n; //outbuf (signature)
		unsigned char *x2buf = NULL; size_t x2n;
		unsigned char *abuf = NULL; size_t an;
		rc = futil::bls_tight::_parse_pub_stream( public_stream,
				NULL, NULL,
				NULL, NULL,
				NULL, NULL,
				&x2buf, &x2n,
				NULL, NULL
				);
		if(rc != 0){
			log_err("Error while parsing public stream! Aborting on error %d",rc);
			if( !x2buf ) free( x2buf );
			pairing_clear( pairing );
			return;
		}
		rc = futil::bls_tight::_parse_sec_stream( secret_stream,
				&abuf, &an,
				NULL, NULL
				);
		if(rc != 0){
			log_err("Error while parsing secret stream! Aborting on error %d",rc);
			if( !x2buf ) free( x2buf );
			if( !abuf ) free( abuf );
			pairing_clear( pairing );
			return;
		}

		//initialize the public/secret params
		element_init_G1(x2, pairing);

		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_Zr(a, pairing);
		element_init_Zr(r, pairing);

		//compressed
		element_from_bytes_compressed( x2, x2buf );

		//secret parsing (this is stable)
		element_from_bytes( a, abuf );

		//obtain message size
		fseek(message_stream, 0, SEEK_END);
		fsize = ftell(message_stream);
		fseek(message_stream, 0, SEEK_SET);  /* same as rewind(f); */

		msgbuf = (char *)malloc(fsize + 1); //allocate for message + null terminator
		fread(msgbuf, 1, fsize, message_stream); //read all into buffer
		msgbuf[fsize] = 0; //add null terminator

		//sample a long from urandom, and obtain a bit from it
		signed long int urandbuf;
		fread( &urandbuf, sizeof(signed long int), 1, urandom_fd ); //read one long into
		debug("urand: %li", urandbuf );
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
		element_from_hash(h, msgbuf, fsize+1);

		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 );

		//compute signature (b is only used for proof)
		element_pow_zn(sig, x2, a);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/30; //millis
		debug("t: %f ms", cpu_time_used );

		// TODO: use utility function to do the below
		//FOR G (SYSTEM PARAM)
		//obtain length to allocate later
		n = pairing_length_in_bytes_x_only_G1(pairing);
		//n = pairing_length_in_bytes_compressed_G2(pairing); //(compressed)
		//n = pairing_length_in_bytes_G2(pairing);
		outbuf = (unsigned char *)malloc( sizeof(unsigned char)* n); //allocate buffer
		//the above buffer can be cleared using pbc_free

		//write to buffer, later we write the buffer to file
		//we can choose to only store the x element because the y element can be 'guessed'
		//https://crypto.stanford.edu/pbc/manual/ch02s02.html
		//the public file is outputted as json format
		element_to_bytes_x_only( outbuf, sig ); //store the x element only
		//element_to_bytes_compressed( outbuf, sig ); //compressed
		//element_to_bytes( outbuf, sig ); //no compression
		debug("Outputting signature element");
		fprintf(sign_stream, "{\"signature\": \""); //prepare to write sys params
		for(i=0;i<n;i++){
			fprintf(sign_stream, "%02X", outbuf[i]);
		}
		fprintf(sign_stream, "\","); //seperator (json style)

		fprintf(sign_stream, "\"r\": \""); //prepare to write sys params
		fprintf(sign_stream, "%li", urandbuf);
		fprintf(sign_stream, "\"}\n"); //seperator (json style)

		//free memory
		free(outbuf);
		free(x2buf);
		free(abuf);
		free(msgbuf);

		//cleanup
		element_clear(x2);
		element_clear(a);
		element_clear(r);
		element_clear(sig);
		element_clear(h);

		pairing_clear(pairing);
		return;
	}

	int verify(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *message_stream,
		FILE *sign_stream
	){
		//vars
		int rc; int out;
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

		char *msgbuf; long fsize; //message buffer
		unsigned char *outbuf; size_t n; //outbuf (signature)
		unsigned char *g2buf = NULL; size_t g2n;
		unsigned char *x2buf = NULL; size_t x2n;
		unsigned char *ybuf = NULL; size_t yn;
		signed long int urandbuf;
		rc = futil::bls_tight::_parse_pub_stream( public_stream,
				NULL, NULL,
				&g2buf, &g2n,
				NULL, NULL,
				&x2buf, &x2n,
				&ybuf, &yn
				);
		if(rc != 0){
			log_err("Error while parsing public stream! Aborting on error %d",rc);
			if( !g2buf ) free( g2buf );
			if( !x2buf ) free( x2buf );
			if( !ybuf ) free( ybuf );
			pairing_clear( pairing );
			return 1;
		}
		rc = futil::bls_tight::_parse_sig_stream( sign_stream, &outbuf, &n, &urandbuf );
		if(rc != 0){
			log_err("Error while parsing signature stream! Aborting on error %d",rc);
			if( !g2buf ) free( g2buf );
			if( !x2buf ) free( x2buf );
			if( !ybuf ) free( ybuf );
			if( !outbuf ) free( outbuf );
			pairing_clear(pairing);
			return 1;
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

		//compressed
		element_from_bytes_compressed( g2, g2buf );
		element_from_bytes_compressed( x2, x2buf );
		element_from_bytes_compressed( y, ybuf );
		element_from_bytes_compressed( sig, outbuf );
		element_set_si( r, urandbuf);

		//obtain message size
		fseek(message_stream, 0, SEEK_END);
		fsize = ftell(message_stream);
		fseek(message_stream, 0, SEEK_SET);  /* same as rewind(f); */

		msgbuf = (char *)malloc(fsize + 1); //allocate for message + null terminator
		fread(msgbuf, 1, fsize, message_stream); //read all into buffer
		msgbuf[fsize] = 0; //add null terminator

		//compute element from hash
		element_from_hash(h, msgbuf, fsize+1);
		element_pow_zn( x2, x2, r );
		element_mul( x2, h, x2 );
		element_pairing( temp1, x2, y );
		element_pairing( temp2, sig, g2);

		if( !element_cmp(temp1, temp2) ){
			//first attemp valid
			log_info("Valid Signature on attempt 1.");
			out = 0;
		} else {
			//try second attempt
			element_invert(temp1, temp1); //invert for the other point
			if (!element_cmp(temp1, temp2)) {
				log_info("Valid Signature on attempt 2.");
				out = 0;
			} else {
				log_info("Invalid Signature.");
				out = 1;
			}

		}

		//free memory
		free(outbuf);
		free(g2buf);
		free(x2buf);
		free(ybuf);
		free(msgbuf);

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
}
