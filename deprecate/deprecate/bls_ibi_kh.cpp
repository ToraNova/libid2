/*
Boneh Lyn Shacham IBI implementation (Kurosawa Heng 2004)
using pbc library from stanford
https://crypto.stanford.edu/pbc/

ToraNova2019
*/

// declaration includes
#include "bls_ibi.hpp"
#include "ptdebug.h"

// custom
#include "futil.hpp"
#include "bls.hpp"

// implementation includes
#include <gmp.h> //gnu multiprecision

// standard lib
#include <string>
#include <cstdlib>
#include <cstdio>

using namespace std;
namespace bls_ibi_kh
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
		bls::keygen(paramstr, pstrlen, public_stream, secret_stream);
		return;
	}

	void extract(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *id_stream, FILE *usk_stream
	){
		//extract is using the msk to sign on an id, resulting in a usk
		bls::sign( paramstr, pstrlen, public_stream, secret_stream, id_stream, usk_stream);
		return;
	}

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

		char *idbuf; long fsize; //id string buffer
		unsigned char *sysbuf = NULL; size_t sysn;
		unsigned char *pubbuf = NULL; size_t pubn;
		unsigned char *uskbuf = NULL; size_t uskn;
		rc = futil::bls::_parse_pub_stream( public_stream, &sysbuf, &sysn, &pubbuf, &pubn);
		if(rc != 0){
			log_err("Error while parsing public stream! Aborting on error %d",rc);
			if( !sysbuf ) free( sysbuf );
			if( !pubbuf ) free( pubbuf );
			pairing_clear(pairing);
			return 1;
		}
		rc = futil::bls::_parse_sig_stream( usk_stream, &uskbuf, &uskn );
		if(rc != 0){
			log_err("Error while parsing user secret key stream! Aborting on error %d",rc);
			if( !sysbuf ) free( sysbuf );
			if( !pubbuf ) free( pubbuf );
			if( !uskbuf ) free( uskbuf );
			pairing_clear(pairing);
			return 1;
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

		debug("syssz: %lu, pubsz: %lu, usk: %lu",sysn,pubn,uskn);
		//x_only
		//element_from_bytes_x_only( g, sysbuf );
		//element_from_bytes_x_only( public_e, pubbuf );
		//compressed
		element_from_bytes_compressed( g, sysbuf );
		element_from_bytes_compressed( public_e, pubbuf );
		element_from_bytes_x_only( usk, uskbuf );

		//debugging prints
		//element_printf("g %B\n", g);
		//element_printf("p %B\n", public_e);
		//element_printf("i %B\n", usk);

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
		element_random(r); //P samples a random r and performs scalar mutliply with hash of ID
		//compute element from hash
		element_from_hash(h, idbuf, fsize+1);
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
		free(sysbuf);
		free(pubbuf);
		free(uskbuf);

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
