/*
 * internals/internals.h - id2 library
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

#ifndef _INTERNALS_HPP_
#define _INTERNALS_HPP_
struct algostr{
	void (*randkeygen)();
	void (*signatgen)( void *, unsigned char *, size_t );
	void (*signatchk)( void *, void *, unsigned char *, size_t );

	void (*secserial)( void *, unsigned char **, size_t *);
	void (*pubserial)( void *, unsigned char **, size_t *);
	void (*sigserial)( void *, unsigned char **, size_t *);
	void (*secstruct)( unsigned char *, size_t);
	void (*pubstruct)( unsigned char *, size_t);
	void (*sigstruct)( unsigned char *, size_t);

	void (*secdestroy)(void *);
	void (*pubdestroy)(void *);
	void (*sigdestroy)(void *);

	void (*secprint)(void *);
	void (*pubprint)(void *);
	void (*sigprint)(void *);

	void (*client)(int, unsigned char *, size_t, void *);
	void (*server)(int, unsigned char *, size_t, void *);
	void (*putest)(void *, void *, unsigned char *, size_t);
};

#include "tnc25519/static.hpp"
#include "tnc25519/proto.hpp"
static struct algostr tnc;
tnc.randkeygen 	= tnc::randomkey;
tnc.signatgen  	= tnc::signatgen;
tnc.signatchk  	= tnc::signatchk;
tnc.secserial 	= tnc::secserial;
tnc.pubserial 	= tnc::pubserial;
tnc.sigserial 	= tnc::sigserial;
tnc.secstruct 	= tnc::secstruct;
tnc.pubstruct 	= tnc::pubstruct;
tnc.sigstruct 	= tnc::sigstruct;
tnc.secdestroy 	= tnc::secdestroy;
tnc.pubdestroy 	= tnc::pubdestroy;
tnc.sigdestroy 	= tnc::sigdestroy;
tnc.secprint 	= tnc::secprint;
tnc.pubprint 	= tnc::pubprint;
tnc.sigprint 	= tnc::sigprint;
tnc.client 	= tnc::client::execute_proto;
tnc.server 	= tnc::server::execute_proto;
tnc.putest 	= tnc::putest;

static struct algostr *incall_main[1] = {
	tnc
};

#define A25519_TNC 		0
#define A25519_CLI 		1	//TODO: not implemented
#define A25519_SCHNORR 		2	//TODO: not implemented
#define A25519_TWINSCHNORR	3	//TODO: not implemented
#define A25519_TIGHTSCHNORR	4	//TODO: not implemented
#define A25519_RESETSCHNORR	5	//TODO: not implemented
#define A25519_RESET2SCHNORR	6	//TODO: not implemented

#endif
