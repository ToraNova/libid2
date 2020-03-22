/*
 * BLS_TIGHT HPP
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _BLS_TIGHT_HPP_
#define _BLS_TIGHT_HPP_

#include <stdio.h> //for the FILE structure

namespace bls_tight
{

	/*
	 * BLS TIGHT keygen
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key output stream (file or stdout)
	 * secret_stream -> the secret key output stream (file or stdout)
	 */
	void keygen(
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
	void sign(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *secret_stream,
		FILE *message_stream, FILE *sign_stream
	);

	/*
	 * BLS TIGHT sign
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * public_stream -> the public key for verification of the resulting sign
	 * message_stream -> for the message to be signed on
	 * sign_stream -> the output signature stream
	 */
	int verify(
		char *paramstr, size_t pstrlen,
		FILE *public_stream, FILE *message_stream,
		FILE *sign_stream
	);

	//optimized namespace, here lies the optimized functions
	namespace opti{
		void keygen(
			char *paramstr, size_t pstrlen,
			FILE *public_stream, FILE *secret_stream
		);

		void sign(
			char *paramstr, size_t pstrlen,
			FILE *public_stream, FILE *secret_stream,
			FILE *message_stream, FILE *sign_stream
		);

		int verify(
			char *paramstr, size_t pstrlen,
			FILE *public_stream, FILE *message_stream,
			FILE *sign_stream
		);

	}
}


#endif
