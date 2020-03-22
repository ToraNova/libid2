/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/

based on the tutorial BLS pairings
ToraNova2019
*/

// declaration includes
#include "bls_ibi.hpp"
#include "ptdebug.h"

// custom
#include "futil.hpp"
#include "bls_tight.hpp"

// implementation includes
#include <pbc/pbc.h> //for the pairing based crypto magic
#include <gmp.h> //gnu multiprecision

// standard lib
#include <string>
#include <cstdlib>
#include <cstdio>

#include <time.h>

using namespace std;
namespace bls_ibi_tight
{
	/*
	 * Setup and Extract are trivial to code, they follow same structure
	 * as the Keygen and Sign of the original BLS signature scheme
	 */
	void setup(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream
	){
		//setup for ibi system is the keygen for msk and usk
		//pubstream is msk while usk is secret_stream
		bls_tight::opti::keygen(paramstr, pstrlen, public_stream, secret_stream);
		return;
	}

	void extract(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *id_stream, FILE *usk_stream
	){
		//extract is using the msk to sign on an id, resulting in a usk
		bls_tight::opti::sign( paramstr, pstrlen, public_stream, secret_stream, id_stream, usk_stream);
		return;
	}


	/*
	 * ORIGINAL unoptimized
	 * Here is the challenge, we need to code the actual HVZKP into this
	 * to simulate a true prover/verifier run
	 * NOTE THAT THIS IS A TEST, NOT THE ACTUAL PROVE/VERIFY ALGO
	 * BECAUSE THEY ARE RAN ON THE SAME MACHINE!
	 */
	int verifytest(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *id_stream,
		FILE *usk_stream
	){

		//vars
		int rc; int out;
		pairing_t pairing;
		element_t r, t, h, usk;
		element_t g1, g2;
		element_t x1, x2, y;
		element_t temp1, temp2, temp3, temp4;
		element_t CMT,CHA,RSP; //random element and the challenge

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		char *idbuf; long fsize; //id string buffer
		unsigned char *uskbuf = NULL; size_t uskn;
		unsigned char *g1buf = NULL; size_t g1n;
		unsigned char *g2buf = NULL; size_t g2n;
		unsigned char *x1buf = NULL; size_t x1n;
		unsigned char *x2buf = NULL; size_t x2n;
		unsigned char *ybuf = NULL; size_t yn;
		signed long int urandbuf;
		rc = futil::bls_tight::_parse_pub_stream( public_stream,
				&g1buf, &g1n,
				&g2buf, &g2n,
				&x1buf, &x1n,
				&x2buf, &x2n,
				&ybuf, &yn
				);
		if(rc != 0){
			log_err("Error while parsing public stream! Aborting on error %d",rc);
			if( !g1buf ) free( g1buf );
			if( !g2buf ) free( g2buf );
			if( !x1buf ) free( x1buf );
			if( !x2buf ) free( x2buf );
			if( !ybuf ) free( ybuf );
			pairing_clear( pairing );
			return 1;
		}
		rc = futil::bls_tight::_parse_sig_stream( usk_stream, &uskbuf, &uskn, &urandbuf );
		if(rc != 0){
			log_err("Error while parsing signature stream! Aborting on error %d",rc);
			if( !g1buf ) free( g1buf );
			if( !g2buf ) free( g2buf );
			if( !x1buf ) free( x1buf );
			if( !x2buf ) free( x2buf );
			if( !ybuf ) free( ybuf );
			if( !uskbuf ) free( uskbuf );
			pairing_clear(pairing);
			return 1;
		}

		//initialize the public/secret params
		element_init_G1(g1, pairing);
		element_init_G1(x1, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_G1(usk, pairing);
		element_init_G2(g2, pairing);
		element_init_G2(y, pairing);
		element_init_Zr(r, pairing);
		element_init_Zr(t, pairing);

		element_init_G1(temp1, pairing);
		element_init_G1(temp2, pairing);

		element_init_GT(temp3, pairing);
		element_init_GT(temp4, pairing);

		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		//debugging print
		debug("g1sz: %lu, g2sz: %lu, x1sz: %lu, x2sz: %lu, ysz: %lu, r: %li",
				g1n,g2n,x1n,x2n,yn, urandbuf);

		//compressed
		element_from_bytes_compressed( g1, g1buf );
		element_from_bytes_compressed( g2, g2buf );
		element_from_bytes_compressed( x1, x1buf );
		element_from_bytes_compressed( x2, x2buf );
		element_from_bytes_compressed( y, ybuf );
		element_from_bytes_compressed( usk, uskbuf );

		element_set_si( r, urandbuf);

		//obtain id string size
		fseek(id_stream, 0, SEEK_END);
		fsize = ftell(id_stream);
		fseek(id_stream, 0, SEEK_SET);  /* same as rewind(f); */

		idbuf = (char *)malloc(fsize + 1); //allocate for id string + null terminator
		fread(idbuf, 1, fsize, id_stream); //read all into buffer
		idbuf[fsize] = 0; //add null terminator

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		// ----- BEGIN TEST -----

		// FIRST PASS
		element_random(t); //P samples a random r and performs scalar mutliply with hash of ID
		//compute element from hash
		element_from_hash(h, idbuf, fsize+1);

		element_pow_zn( temp1, x2, r );
		element_mul( temp2, h, temp1 ); //compute H(id) * x2^-r

		//performs scalar multiply (raise to power)
		element_pow_zn( CMT, temp2, t); // CMT = (H(id) * x2^-r) ^t , r
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
		element_pow_zn( temp1, temp2, CHA );
		element_mul( temp1, CMT, temp1 );

		element_pairing(temp3, temp1, y);
		element_pairing(temp4, RSP, g2);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/30; //millis
		debug("t: %f ms", cpu_time_used );

		if( !element_cmp(temp3, temp4) ){
			//first attemp valid
			debug("Valid Verification on attempt 1.");
			out = 0;
		} else {
			//try second attempt
			element_invert(temp3, temp3); //invert for the other point
			if (!element_cmp(temp3, temp4)) {
				debug("Valid Verfication on attempt 2.");
				out = 0;
			} else {
				debug("Verification Test Failed.");
				out = 1;
			}

		}

		//free memory
		free(idbuf);
		free(uskbuf);
		free(g1buf);
		free(g2buf);
		free(x1buf);
		free(x2buf);
		free(ybuf);

		//cleanup
		element_clear(g1);
		element_clear(g2);
		element_clear(x1);
		element_clear(x2);
		element_clear(y);
		element_clear(usk);
		element_clear(h);
		element_clear(t);
		element_clear(temp1);
		element_clear(temp2);
		element_clear(temp3);
		element_clear(temp4);
		element_clear(r);
		element_clear(CMT);
		element_clear(CHA);
		element_clear(RSP);
		pairing_clear(pairing);

		//return result
		return out;
	}

	namespace opti{
	/*
	 * Here is the challenge, we need to code the actual HVZKP into this
	 * to simulate a true prover/verifier run
	 * NOTE THAT THIS IS A TEST, NOT THE ACTUAL PROVE/VERIFY ALGO
	 * BECAUSE THEY ARE RAN ON THE SAME MACHINE!
	 */
	int verifytest(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *id_stream,
		FILE *usk_stream
	){

		//vars
		int rc; int out;
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

		char *idbuf; long fsize; //id string buffer
		unsigned char *uskbuf = NULL; size_t uskn;
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
		rc = futil::bls_tight::_parse_sig_stream( usk_stream, &uskbuf, &uskn, &urandbuf );
		if(rc != 0){
			log_err("Error while parsing signature stream! Aborting on error %d",rc);
			if( !g2buf ) free( g2buf );
			if( !x2buf ) free( x2buf );
			if( !ybuf ) free( ybuf );
			if( !uskbuf ) free( uskbuf );
			pairing_clear(pairing);
			return 1;
		}

		//initialize the public/secret params
		element_init_G2(g2, pairing);
		element_init_G1(x2, pairing);
		element_init_G1(h, pairing);
		element_init_G1(usk, pairing);
		element_init_G2(y, pairing);
		element_init_Zr(r, pairing);
		element_init_Zr(t, pairing);

		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);

		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		//debugging print
		debug("g2sz: %lu, x2sz: %lu, ysz: %lu, r: %li",
				g2n,x2n,yn, urandbuf);

		//compressed
		element_from_bytes_compressed( g2, g2buf );
		element_from_bytes_compressed( x2, x2buf );
		element_from_bytes_compressed( y, ybuf );
		element_from_bytes_compressed( usk, uskbuf );
		element_set_si( r, urandbuf);

		//obtain id string size
		fseek(id_stream, 0, SEEK_END);
		fsize = ftell(id_stream);
		fseek(id_stream, 0, SEEK_SET);  /* same as rewind(f); */

		idbuf = (char *)malloc(fsize + 1); //allocate for id string + null terminator
		fread(idbuf, 1, fsize, id_stream); //read all into buffer
		idbuf[fsize] = 0; //add null terminator

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		// ----- BEGIN TEST -----

		// FIRST PASS
		element_random(t); //P samples a random r and performs scalar mutliply with hash of ID
		//compute element from hash
		element_from_hash(h, idbuf, fsize+1);

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
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/30; //millis
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

		//free memory
		free(idbuf);
		free(uskbuf);
		free(g2buf);
		free(x2buf);
		free(ybuf);

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
