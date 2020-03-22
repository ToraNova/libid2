/*
  Wrapper for vbls.hpp
  consist of function calls for
  SS and IBI algorithms
  Made for paircrypt

  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _VBLS_H_
#define _VBLS_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C"{
#endif

	/*
	 * vBLS keygen
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param (in)
	 * pstrlen -> length of param string (in)
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 * please free up pbuffer and sbuffer after use !
	 */
	int vbls_ss_keygen(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * vBLS sign
	 * returns 0 on success and 1 on error
	 * Signs on a message string
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (out)
	 * plen -> output length of pbuffer (in)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (out)
	 */
	int vbls_ss_sign(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * vBLS verify
	 * returns 0 on success and 1 on error
	 * Verifies if a message is signed by the secret key of a particular public key
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (in)
	 */
	int vbls_ss_verify(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	/*
	 * vBLS IBI setup
	 * returns 0 on success and 1 on error
	 * Setup the mpk and msk
	 * paramstr -> a string representation of param (in)
	 * pstrlen -> length of param string (in)
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 */
	int vbls_ibi_setup(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * vBLS IBI extract
	 * returns 0 on success and 1 on error
	 * Extract the usk from mpk/msk
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing user id (in)
	 * obuffer -> output buffer for usk (out)
	 * plen -> output length of pbuffer (in)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of user id string (in)
	 * olen -> length of usk buffer (out)
	 */
	int vbls_ibi_extract(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * vBLS IBI prove
	 * The PROVER runs this, essentially
	 * attempts to prove identity of the prover
	 * to a verifier
	 * RETURN 0 on success
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing user id (in)
	 * obuffer -> output buffer for usk (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of user id string (in)
	 * olen -> length of usk buffer (in)
	 * port -> port number of verifier
	 * srv -> address of verifier
	 * timeout -> seconds to timeout
	 */
	int vbls_ibi_prove(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int port, const char *srv,
		int timeout
	);

	/*
	 * vBLS IBI verify
	 * The VERIFIER runs this, essentially
	 * attempts to verify an incoming connection
	 * with their identity.
	 * return 0 if their valid, 1 otherwise
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * plen -> output length of pbuffer (in)
	 * mbuffer -> the buffer holding the id prover (out)
	 * mlen -> output length of mbuffer (out)
	 * port -> which port to bind the verifier to?
	 * timeout -> seconds to timeout
	 */
	int vbls_ibi_verify(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	);

	/*
	 * vBLS IBI verifytest
	 * VerifyTest - test verification
	 * returns 0 on success and 1 on error
	 * paramstr -> a string representation of param
	 * pstrlen -> length of param string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing userid (in)
	 * obuffer -> output buffer for usk (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of user id string (in)
	 * olen -> length of usk buffer (in)
	 * THIS IS ONLY FOR TESTING NOT THE ACTUAL PROVE/VERIFY ALGO
	 * This includes a self simulated HVZKP running
	 */
	int vbls_ibi_verifytest(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);


#ifdef __cplusplus
}
#endif

#endif
