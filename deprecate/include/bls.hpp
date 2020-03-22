/*
 * BLS hpp file for the BLS signature scheme
 * and BLS IBI scheme (Kurosawa-Heng)
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _BLS_HPP_
#define _BLS_HPP_

#include <stddef.h>

namespace bls
{

	//standard signature scheme
	namespace ss{

	/*
	 * BLS keygen
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
	int keygen(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * BLS sign
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
	int sign(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * BLS verify
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
	int verify(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	}

	//id based id scheme
	namespace ibi{
	/*
	 * Setup the mpk and msk
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
	 * paramstr -> a string representation of param (in)
	 * pstrlen -> length of param string (in)
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 */
	int setup(
		char *paramstr, size_t pstrlen,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * Extract the usk from mpk/msk
	 * returns 0 on success and 1 on error
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
	int extract(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * VerifyTest - test verification
	 * returns 0 on success and 1 on error
	 * Generates a public key based on pairing type
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
	int verifytest(
		char *paramstr, size_t pstrlen,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	}
}


#endif
