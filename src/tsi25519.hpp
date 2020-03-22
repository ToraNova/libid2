/*
  IBI based on Ed25519 signature scheme by Bernstein

  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _TSI25519_HPP_
#define _TSI25519_HPP_

#include <stddef.h>

namespace ts25519 {
	//BASED ON TNC Schnorr signatures using
	//Finite-Field arithmetic with Ristretto over 25519

	/*
	 * TS25519 Signatures Keygen
	 * Generates a public key for Ed25519 DSA
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 * please free up pbuffer and sbuffer after use !
	 */
	int keygen(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * TS25519 Signatures Sign
	 * Signs on a message string
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (out)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (out)
	 */
	int sign(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * TS25519 Signatures Verify
	 * returns 0 on success and 1 on error
	 * Verifies if a message is signed by the sk of corresponding pk
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of message string (in)
	 * olen -> length of signature buffer (in)
	 */
	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);
}

namespace ti25519 {
	/*
	 * IBI based on TS25519 Setup
	 * Generates the master public key
	 * pbuffer -> the buffer holding the pubkey (out)
	 * sbuffer -> the buffer holding the seckey (out)
	 * plen -> output length of pbuffer (out)
	 * slen -> output length of sbuffer (out)
	 * please free up pbuffer and sbuffer after use !
	 */
	int setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	/*
	 * TI25519 IBI Extract
	 * Extracts a user key based on ID and msk
	 * sbuffer -> the buffer holding the seckey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (out)
	 * slen -> output length of sbuffer (in)
	 * mlen -> length of message string (in) (ID String)
	 * olen -> length of signature buffer (out) (USK)
	 */
	int extract(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	/*
	 * TI25519 IBI Prove
	 * The PROVER runs this, essentially
	 * attempts to prove itself to a verifier on otherside of the tcp socket
	 * return 0 if success, 1 otherwise
	 * mbuffer -> the buffer holding the ID string (in)
	 * mlen -> input length of mbuffer (in)
	 * obuffer -> the buffer of the user attempting to ID (in)
	 * olen -> input length of obuffer (in)
	 * csock -> tcp socket to the prover (in)
	 * timeout -> tcp socket timeout (in)
	 * DO NOT WRITE ANYTHING TO CSOCK while PROVE has not RETURNED!
	 */
	int prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int csock
	);

	/*
	 * TI25519 IBI Verify
	 * The VERIFIER runs this, essentially
	 * attempts to verify an incoming connection
	 * return 0 if success, 1 otherwise
	 * pbuffer -> the buffer holding the pubkey (in)
	 * plen -> length of pbuffer (in)
	 * mbuffer -> the buffer of the user attempting to ID (out)
	 * mlen -> length of mbuffer (out)
	 * csock -> tcp socket to the prover (in)
	 * timeout -> tcp socket timeout (in)
	 * DO NOT WRITE ANYTHING TO CSOCK while VERIFY has not RETURNED!
	 */
	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int csock
	);

	/*
	 * TI25519 IBI One-shot client
	 * The PROVER runs this, essentially
	 * attempts to prove identity of the prover
	 * to a verifier
	 * RETURN 0 on success
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
	int oclient(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout

	);

	/* TI25519 IBI One-shot server
	 * attempt verification ONCE only, shutdown after
	 * useful for tests. return 0 if valid and 1 otherwise
	 * pbuffer -> the buffer holding the pubkey (in)
	 * plen -> output length of pbuffer (in)
	 * mbuffer -> the buffer of the user attempting to ID (out)
	 * mlen -> output length of mbuffer (out)
	 * port -> which port to bind the verifier to?
	 * timeout -> seconds to timeout
	 *
	 */
	int oserver(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	);

	/*
	 * TI25519 IBI Client
	 * The PROVER runs this, essentially
	 * attempts to prove identity of the prover
	 * to a verifier
	 * RETURN -1 when failed to prove
	 * else, RETURN a socket descriptor to communicate further
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing user id (in)
	 * obuffer -> output buffer for usk (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of user id string (in)
	 * olen -> length of usk buffer (in)
	 * port -> port number of verifier
	 * srv -> address of verifier
	 * timeout -> seconds to timeout
	 * PLEASE CLOSE THE SOCKET YOURSELF AFTER USING.
	 */
	int client(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout
	);

	/*
	 * TI25519 IBI Server
	 * The VERIFIER runs this, essentially
	 * attempts to verify an incoming connection
	 * with their identity.
	 * return 0 if their valid, 1 otherwise
	 * pbuffer -> the buffer holding the pubkey (in)
	 * plen -> output length of pbuffer (in)
	 * callback -> callback function to use when someone verifies
	 * port -> which port to bind the verifier to?
	 * timeout -> seconds to timeout
	 * maxcq -> maximum number of conections to queue while busy
	 *
	 * sample callback template:
	 * void ti25519_callback( int rc, const char *mbuffer, size_t mlen, int csock ){
	 * 	// rc is 0 iff mbuffer possess a valid usk
	 * 	// do something with mbuffer and mlen based on rc
	 *	// csock is the socket used to talk to the client
	 *
	 *	return;
	 * }
	 */
	void server(
		unsigned char *pbuffer, size_t plen,
		void (*callback)(int, int, const unsigned char *, size_t),
		int port, int timeout, int maxcq
	);

	/*
	 * TI25519 IBI verifytest
	 * returns 0 on success and 1 on error
	 * Verifies that a usk/id pair can be validated correctly to a msk
	 * pbuffer -> the buffer holding the pubkey (in)
	 * mbuffer -> input buffer containing message (in)
	 * obuffer -> output buffer for signaturre (in)
	 * plen -> output length of pbuffer (in)
	 * mlen -> length of message string (in) (ID String)
	 * olen -> length of signature buffer (in) (USK)
	 */
	int verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	//sample callback
	void sample_callback(int rc, int csock, const unsigned char *mbuf, size_t mlen);

	//timing tests for client and server
	//client
	void tclient(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int count
	);
	//server
	void tserver(
		unsigned char *pbuffer, size_t plen,
		int port, int count
	);

}

#define ELE crypto_core_ristretto255_BYTES
#define SCA crypto_core_ristretto255_SCALARBYTES

#endif
