/*
 * a25519.h - id2 library
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Chia Jason
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * File: a25519.h (algorithm for curve25519 based IBI and signatures)
 * Signature and identity-based identification algorithms
 * based of Finite-field arithmetic over Curve25519 (libsodium)
 * https://nacl.cr.yp.to/install.html
 * Toranova 2019
 * chia_jason96@live.com
*/

#ifndef _A25519_H_
#define _A25519_H_

#include <stddef.h>

//TS - tight signature
//TI - tight identity based identification

#ifdef __cplusplus
extern "C"{
#endif

	int a25519_keygen(
		unsigned int algotype,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	int a25519_sig_sign(
		unsigned int algotype,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	);

	int a25519_sig_verify(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	int a25519_ibi_prove(
		unsigned int algotype,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int csock
	);

	int a25519_ibi_verify(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int csock
	);

	int a25519_ibi_oclient(
		unsigned int algotype,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout
	);

	int a25519_ibi_oserver(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	);

	int a25519_ibi_client(
		unsigned int algotype,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout
	);

	/*
	 * sample callback template:
	 * void sample_callback( int rc, const char *mbuffer, size_t mlen, int csock ){
	 * 	// rc is 0 iff mbuffer possess a valid usk
	 * 	// do something with mbuffer and mlen based on rc
	 *	// csock is the socket used to talk to the client
	 *
	 *	return;
	 * }
	 */
	void a25519_ibi_server(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		int port, int timeout, int maxcq,
		void (*callback)(int, int, const unsigned char *, size_t)
	);


	int a25519_test_offline(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	);

	//timing tests for client and server
	//count -- number of instances to run
	void a25519_test_client(
		unsigned int algotype,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		unsigned int count
	);
	//server
	void a25519_test_server(
		unsigned int algotype,
		unsigned char *pbuffer, size_t plen,
		int port, unsigned int count
	);


#ifdef __cplusplus
}
#endif

#endif
