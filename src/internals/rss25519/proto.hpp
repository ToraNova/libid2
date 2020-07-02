/*
 * internals/rss25519/proto.hpp - id2 library
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
 * TODO: please edit description
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is (mainly) for internal use only!
 */

#ifndef _RSS25519_PROTO_HPP_
#define _RSS25519_PROTO_HPP_

#include <stddef.h>
#include "static.hpp"

namespace rss25519 {

	//prove existence of usk without revealing
	int signatprv(
		int sock,
		void *vusk,
		const unsigned char *mbuffer, size_t mlen
	);

	//verify existence of usk of particular mbuffer(ID)
	int signatvrf(
		int sock,
		void *vpar,
		const unsigned char *mbuffer, size_t mlen
	);

	// an auxiliary function to test param and usk
	int prototest(
		void *vpar,
		void *vusk,
		const unsigned char *mbuffer, size_t mlen
	);
}

#endif
