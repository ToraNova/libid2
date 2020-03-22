/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/

based on the tutorial BLS pairings
ToraNova2019
*/

// declaration includes
#include "bls.hpp"
#include "ptdebug.h"

// implementation includes
#include <pbc/pbc.h> //for the pairing based crypto magic
#include <gmp.h> //gnu multiprecision

// standard lib
#include <cstdlib>
#include <cstdio>
#include <time.h>

using namespace std;
namespace bls
{
	namespace ss{

	int keygen(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//vars
		pairing_t pairing;
		element_t g;
		element_t public_e, secret_e;
		size_t n; int rc; //n used for size storage and rc for result code

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the public params
		element_init_G2(g, pairing);
		element_init_G2(public_e, pairing);
		element_init_Zr(secret_e, pairing);

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		//generates secret key and public key
		element_random(g);
		element_random(secret_e);
		element_pow_zn(public_e, g, secret_e);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		debug("t: %f ms", cpu_time_used );

		//calculate the amount of memory required for public and secret key, then allocate
		n = pairing_length_in_bytes_compressed_G2(pairing);
		debug("G2 sz: %lu",n);
		n = 2 * n; //2 pubkey element G2
		*pbuffer = (unsigned char *)malloc( n );
		*plen = n;
		debug("Pk sz: %lu",*plen);

		n = pairing_length_in_bytes_Zr(pairing); //one pubkey
		debug("Zr sz: %lu",n);
		*sbuffer = (unsigned char *)malloc( n );
		*slen = n;
		debug("Sk sz: %lu",*slen);


		/*
		we can choose to only store the x element because the y element can be 'guessed'
		https://crypto.stanford.edu/pbc/manual/ch02s02.html
		FOR G (SYSTEM PARAM)
		obtain length to allocate later
		n = pairing_length_in_bytes_x_only_G2(pairing);
		n = pairing_length_in_bytes_compressed_G2(pairing); //(compressed)
		n = pairing_length_in_bytes_G2(pairing);
		alt: element_from_bytes_x_only
		alt: element_from_bytes
		*/

		element_to_bytes_compressed( *pbuffer, g ); //write g first
		element_to_bytes_compressed( *pbuffer+(*plen/2), public_e ); //then public_e
		element_to_bytes( *sbuffer, secret_e );

		//cleanup
		element_clear(g);
		element_clear(public_e);
		element_clear(secret_e);
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
		element_t g;
		element_t public_e, secret_e;
		element_t sig, h;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the public params
		element_init_G2(g, pairing);
		element_init_G2(public_e, pairing);
		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_Zr(secret_e, pairing);

		element_from_bytes_compressed( g, pbuffer );
		element_from_bytes_compressed( public_e, pbuffer + (plen/2) );
		element_from_bytes( secret_e, sbuffer );

		/*
		THERE ARE SOME BYTE ERRORS Oct 14 2019 ToraNova
		update: it appears that the function element_from is
		somewhat deterministic, sometimes the element read is the same
		while other time it is not. perhaps it differs based on pairing?
		x_only seems to fix it as of now...
		PARAMS MUST NOT BE GENERATED ON THE FLY!
		*/

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		//compute element from hash
		element_from_hash(h, mbuffer, mlen);
		//compute signature
		element_pow_zn(sig, h, secret_e);

		end = clock();
		cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
		debug("t: %f ms", cpu_time_used );

		//calculate the amount of memory required for public and secret key, then allocate
		n = pairing_length_in_bytes_x_only_G1(pairing);
		debug("G1 sz: %lu",n);
		*obuffer = (unsigned char *)malloc( n );
		*olen = n;
		debug("Out sz: %lu",*olen);
		debug("M sz: %lu",mlen);

		element_to_bytes_x_only( *obuffer, sig ); //store the x element only

		//cleanup
		element_clear(g);
		element_clear(public_e);
		element_clear(secret_e);
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
		int rc; int out;
		pairing_t pairing;
		element_t g;
		element_t public_e;
		element_t sig, h;
		element_t temp1, temp2;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the public params
		element_init_G2(g, pairing);
		element_init_G2(public_e, pairing);
		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);

		element_from_bytes_compressed( g, pbuffer );
		element_from_bytes_compressed( public_e, pbuffer + (plen/2) );
		element_from_bytes_x_only( sig, obuffer );

		//compute element from hash
		element_from_hash(h, mbuffer, mlen);

		element_pairing(temp1, sig, g);
		element_pairing(temp2, h, public_e);
		if( !element_cmp(temp1, temp2) ){
			//first attemp valid
			debug("Valid Signature on attempt 1.");
			out = 0;
		} else {
			//try second attempt
			element_invert(temp1, temp1); //invert for the other point
			if (!element_cmp(temp1, temp2)) {
				debug("Valid Signature on attempt 2.");
				out = 0;
			} else {
				debug("Invalid Signature.");
				out = 1;
			}

		}

		//cleanup
		element_clear(g);
		element_clear(public_e);
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
		int rc; int out;
		pairing_t pairing;
		element_t g;
		element_t r; //random element and the challenge
		element_t CMT,CHA,RSP; //random element and the challenge
		element_t public_e;
		element_t usk, h;
		element_t temp1, temp2, temp3, temp4;

		if(paramstr == NULL || pstrlen <= 0){
			log_err("Invalid paramstr");
			return 1;
		}else{
			//else initialize pairing directly
			rc = pairing_init_set_buf(pairing, paramstr, pstrlen);
			if( rc != 0 ) { log_err("Paramstr setbuf failed"); return 1; }
		}

		//initialize the params
		element_init_G2(g, pairing);
		element_init_G2(public_e, pairing);
		element_init_G1(h, pairing);
		element_init_G1(usk, pairing);
		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);

		element_init_Zr(temp3, pairing); // hold r+CMT
		element_init_G1(temp4, pairing);
		element_init_Zr(r, pairing); //random element to 'hide' the ID hash

		element_init_Zr(CHA, pairing); //challenge is a 256bit int
		element_init_G1(CMT, pairing); //CMT is a group element
		element_init_G1(RSP, pairing); //CMT is a group element

		element_from_bytes_compressed( g, pbuffer );
		element_from_bytes_compressed( public_e, pbuffer + (plen/2) );
		element_from_bytes_x_only( usk, obuffer );

		//debugging lines
		clock_t start, end;
		double cpu_time_used;
		start = clock();

		// ----- BEGIN TEST -----

		// FIRST PASS
		element_random(r); //P samples a random r and performs scalar mutliply with hash of ID
		//compute element from hash
		element_from_hash(h, mbuffer, mlen);
		//performs scalar multiply (raise to power)
		element_pow_zn( CMT, h, r); // CMT = h^r where h = H(ID)
		// CMT is sent to V

		// SECOND PASS
		// V samples a challenge and sends it to P
		element_random(CHA);

		// THIRD PASS
		// P computes the RSP
		element_add(temp3, r, CMT); //compute r+CMT
		element_pow_zn( RSP, usk, temp3); // RSP = d^(r+CMT)
		// RSP is sent back to V

		// V test
		// compute H(ID)^(r+CHA)
		element_pow_zn( temp4, h, temp3 );
		element_pairing(temp1, RSP, g);
		element_pairing(temp2, temp4, public_e);

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
		element_clear(g);
		element_clear(public_e);
		element_clear(usk);
		element_clear(h);
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

	}
}
