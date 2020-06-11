/*
 * a25519.c.cpp - id2 library
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
 * File: a25519.c.cpp (algorithm for curve25519 based IBI and signatures)
 * Signature and identity-based identification algorithms
 * based of Finite-field arithmetic over Curve25519 (libsodium)
 * https://nacl.cr.yp.to/install.html
 * Toranova 2019
 * chia_jason96@live.com
*/

#include "a25519.h"
#include "a25519.hpp"

int a25519_keygen(
	unsigned int algotype,
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return a25519::keygen(algotype,pbuffer, plen, sbuffer, slen);
}

int a25519_sig_sign(
	unsigned int algotype,
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return a25519::sig::sign(algotype,sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int a25519_sig_verify(
	unsigned int algotype,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return a25519::sig::verify(algotype,pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int a25519_ibi_oclient(
	unsigned int algotype,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	int timeout
){
	return a25519::ibi::oclient(algotype,mbuffer, mlen, obuffer, olen, srv, port, timeout);
}

int a25519_ibi_oserver(
	unsigned int algotype,
	unsigned char *pbuffer, size_t plen,
	unsigned char **mbuffer, size_t *mlen,
	int port, int timeout
){
	return a25519::ibi::oserver(algotype,pbuffer, plen, mbuffer, mlen, port, timeout);
}

int a25519_ibi_client(
	unsigned int algotype,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	int timeout
){
	return a25519::ibi::client(algotype,mbuffer, mlen, obuffer, olen, srv, port, timeout);
}

void a25519_ibi_server(
	unsigned int algotype,
	unsigned char *pbuffer, size_t plen,
	int port, int timeout, int maxcq,
	void (*callback)(int, int, const unsigned char *, size_t)
){
	a25519::ibi::server(algotype,pbuffer, plen, port, timeout, maxcq, callback);
}

int a25519_test_offline(
	unsigned int algotype,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return a25519::test::offline(algotype,pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

//timing tests
//client
void a25519_test_client(
	unsigned int algotype,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	unsigned int count
){
	a25519::test::client(algotype,mbuffer,mlen,obuffer,olen,srv,port,count);
}

//server
void a25519_test_server(
	unsigned int algotype,
	unsigned char *pbuffer, size_t plen,
	int port, unsigned int count
){
	a25519::test::server(algotype,pbuffer,plen,port,count);
}
