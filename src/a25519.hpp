/*
 * a25519.hpp - id2 library
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
 * File: a25519.hpp (algorithm for curve25519 based IBI and signatures)
 * Signature and identity-based identification algorithms
 * based of Finite-field arithmetic over Curve25519 (libsodium)
 * https://nacl.cr.yp.to/install.html
 * Toranova 2019
 * chia_jason96@live.com
*/
#ifndef _A25519_HPP_
#define _A25519_HPP_

#include <stddef.h>

namespace a25519 {

	int keygen(
		unsigned int algotype,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	);

	namespace sig{
		int sign(
			unsigned int algotype,
			unsigned char *sbuffer, size_t slen,
			unsigned char *mbuffer, size_t mlen,
			unsigned char **obuffer, size_t *olen
		);

		int verify(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen
		);

		//TODO: implement the following methods
		//following 2 are for certificateless schemes
		//compute user secret value and upk1
		int setuserkey(
			unsigned int algotype,
			unsigned char **ubuffer, size_t *ulen
		);

		//ppk - obuffer, sv,upk - ubuffer
		//fbuffer contains upk and usk
		int setuprvkey(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char *obuffer, size_t olen,
			unsigned char *ubuffer, size_t ulen,
			unsigned char *mbuffer, size_t mlen,
			unsigned char **fbuffer, size_t *flen
		);

	}

	namespace ake{

		int execute(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char *obuffer, size_t olen
		)

	}

	namespace ibi{

		int prove(
			unsigned int algotype,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen,
			int csock
		);

		int verify(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char **mbuffer, size_t *mlen,
			int csock
		);

		int oclient(
			unsigned int algotype,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen,
			const char *srv, int port,
			int timeout
		);

		int oserver(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char **mbuffer, size_t *mlen,
			int port, int timeout
		);

		int client(
			unsigned int algotype,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen,
			const char *srv, int port, int timeout
		);

		/*
		 * sample callback template:
		 * void sample( int rc, const char *mbuffer, size_t mlen, int csock ){
		 * 	// rc is 0 iff mbuffer possess a valid usk
		 * 	// do something with mbuffer and mlen based on rc
		 *	// csock is the socket used to talk to the client
		 *	return;
		 * }
		 */
		void server(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			int port, int timeout, int maxcq,
			void (*callback)(int, int, const unsigned char *, size_t)
		);
	}

	namespace test{

		//verify a ID-usk pair works for the pk
		int offline(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen
		);

		//timing tests for client and server
		// count -- number of instances to run
		void client(
			unsigned int algotype,
			unsigned char *mbuffer, size_t mlen,
			unsigned char *obuffer, size_t olen,
			const char *srv, int port,
			unsigned int count
		);
		void server(
			unsigned int algotype,
			unsigned char *pbuffer, size_t plen,
			int port, unsigned int count
		);
	}

}

#endif
