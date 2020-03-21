/*
  Wrapper for i25519.hpp
  Made for id2

  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _TSI25519_H_
#define _TSI25519_H_

#include <stddef.h>

//TS - tight signature
//TI - tight identity based identification

#ifdef __cplusplus
extern "C"{
#endif

	/*
	 * Ed25519 Keygen (based on NaCL, this function just standardizes my own syntax)
	 * Generates a public key for Ed25519 DSA
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 * please free up pbuffer and sbuffer after use !
	 */
	int ts25519_keygen(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * Ed25519 Sign (based on NaCL, this function just standardizes it with my own syntax)
	 * Signs on a message string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (out)
	 * plen -> output length of pbuffer (in)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (out)
	 */
	int ts25519_sign(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * Ed25519 Verify (based on NaCL, this function just standardizes it with my own syntax)
	 * returns 0 on success and 1 on error
	 * Verifies if a message is signed by the secret key of a particular public key
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (in)
	 */
	int ts25519_verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	/*
	 * Ed25519 IBI Setup (based on NaCL, this function just standardizes my own syntax)
	 * Generates a public key for Ed25519 DSA
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 * please free up pbuffer and sbuffer after use !
	 */
	int ti25519_setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * Ed25519 Extract (based on NaCL, this function just standardizes it with my own syntax)
	 * Signs on a message string
	 * pbuffer -> the buffer holding the pubkey (in)
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (out)
	 * plen -> output length of pbuffer (in)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of message string (in) (ID String)
	 * olen -> length of signature buffer (out) (USK)
	 */
	int ti25519_extract(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * EdDSA IBI prove
	 * The PROVER runs this, essentially
	 * attempts to prove identity of the prover
	 * to a verifier
	 * RETURN 0 on success
	 * mbuffer -> input buffer containing user id (in)
	 * obuffer -> output buffer for usk (in)
	 * mlen -> length of user id string (in)
	 * olen -> length of usk buffer (in)
	 * port -> port number of verifier
	 * srv -> address of verifier
	 * timeout -> seconds to timeout
	 */
	int ti25519_prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int port, const char *srv,
		int timeout
	);

	/*
	 * EdDSA IBI verify
	 * The VERIFIER runs this, essentially
	 * attempts to verify an incoming connection
	 * with their identity.
	 * return 0 if their valid, 1 otherwise
	 * pbuffer -> the buffer holding the pubkey (in)
	 * plen -> output length of pbuffer (in)
	 * mbuffer -> the buffer of the user attempting to ID (out)
	 * mlen -> output length of mbuffer (out)
	 * port -> which port to bind the verifier to?
	 * timeout -> seconds to timeout
	 */
	int ti25519_verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	);

	/*
	 * Ed25519 verifytest (based on NaCL, this function just standardizes it with my own syntax)
	 * returns 0 on success and 1 on error
	 * Verifies if a message is signed by the secret key of a particular public key
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of message string (in) (ID String)
	 * olen -> length of signature buffer (in) (USK)
	 */
	int ti25519_verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);


#ifdef __cplusplus
}
#endif

#endif
