/*
  Wrapper for bls_tight.hpp
  Made for paircrypt

  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _BLS_TIGHT_H_
#define _BLS_TIGHT_H_

#include <pbc/pbc.h>

#ifdef __cplusplus
extern "C"{
#endif


	/*
	 * BLS TIGHT keygen
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key output stream (file or stdout)
	 * secret_stream -> the secret key output stream (file or stdout)
	 */
	void bls_tight_keygen(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream
	);

	/*
	 * BLS TIGHT sign
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * secret_stream -> the secret key file (or stdin) used to sign
	 * message_stream -> for the message to be signed on
	 * sign_stream -> the output signature stream
	 */
	void bls_tight_sign(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *message_stream, FILE *sign_stream
	);

	/*
	 * BLS TIGHT sign
	 * returns 0 for OK and 1 for error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * message_stream -> for the message to be signed on
	 * sign_stream -> the output signature stream
	 */
	int bls_tight_verify(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *message_stream,
		FILE *sign_stream
	);

#ifdef __cplusplus
}
#endif

#endif
