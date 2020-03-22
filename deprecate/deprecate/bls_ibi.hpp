/*
  Made for the makefile template project
  For IBI using pairing operations (BLS-ibi and tight BLS-ibi)
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _BLS_IBI_HPP_
#define _BLS_IBI_HPP_

#include <stdio.h> //for the FILE structure

/*
 * BLS-IBI Kurosawa-Heng 2004
 * Setup/Extract/VerifyTest/Verify/Prove algorithms
 * TODO: create tcp method for verify (prover/verifier)
 */
namespace bls_ibi_kh
{

	/*
	 * Setup the mpk and msk
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public param output stream (file or stdout)
	 * secret_stream -> the master secret key output stream (file or stdout)
	 */
	void setup(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream
	);

	/*
	 * Extract the usk from mpk/msk
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * secret_stream -> the secret key file (or stdin) used to sign
	 * id_stream -> publicly identifiable string to represent a user/entity
	 * usk_stream -> the user secret key extracted
	 */
	void extract(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *id_stream, FILE *usk_stream
	);

	/*
	 * VerifyTest - test verification
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * id_stream -> the user identity to identity itself as
	 * usk_stream -> the usk
	 * THIS IS ONLY FOR TESTING NOT THE ACTUAL PROVE/VERIFY ALGO
	 * This includes a self simulated HVZKP running
	 */
	int verifytest(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *id_stream,
		FILE *usk_stream
	);
}

namespace bls_ibi_tight
{

	/*
	 * Setup the mpk and msk
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public param output stream (file or stdout)
	 * secret_stream -> the master secret key output stream (file or stdout)
	 */
	void setup(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream
	);

	/*
	 * Extract the usk from mpk/msk
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * secret_stream -> the secret key file (or stdin) used to sign
	 * id_stream -> publicly identifiable string to represent a user/entity
	 * usk_stream -> the user secret key extracted
	 */
	void extract(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *id_stream, FILE *usk_stream
	);

	/*
	 * VerifyTest - test verification
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * id_stream -> the user identity to identity itself as
	 * usk_stream -> the usk
	 * THIS IS ONLY FOR TESTING NOT THE ACTUAL PROVE/VERIFY ALGO
	 * This includes a self simulated HVZKP running
	 */
	int verifytest(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *id_stream,
		FILE *usk_stream
	);

	namespace opti{

	int verifytest(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *id_stream,
		FILE *usk_stream
	);

	}
}


#endif
