/*
 * internals/tnc25519/proto.hpp - id2 library
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
 * TNCIBI protocol scheme
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is (mainly) for internal use only!
 */

#ifndef _TNC25519_PROTO_HPP_
#define _TNC25519_PROTO_HPP_

#include <stddef.h>
#include "static.hpp"

namespace tnc25519 {

	namespace client{

		// execute ibi protocol as client
		// sock - the socket connection to server
		// mbuffer, mlen - id of user/prover
		// usk - usk struct (signature) of prover
		int executeproto(
			int sock,
			unsigned char *mbuffer, size_t mlen,
			struct signat *usk
		);

	}

	namespace server{

		// execute ibi protocol as server
		// sock - the socket connection to client
		// par - the parameter of ibi system (public key of kgc)
		// mbuffer - the client identifying on other end (OUTPUT)
		int executeproto(
			int sock,
			unsigned char *mbuffer, size_t mlen,
			struct pubkey *par
		);

	}

	// an auxiliary function to test param and usk
	int putest(
		struct pubkey *par,
		struct signat *usk,
		unsigned char *mbuffer, size_t mlen
	);
}

#endif
