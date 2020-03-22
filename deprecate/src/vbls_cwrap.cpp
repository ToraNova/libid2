/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/
This is the wrapper for the c-library, id2 supports c/c++ implementations
Last edit : 01 Jan 2020  -- ToraNova2019

The MIT License (MIT)

Copyright (c) 2019 Chia Jason

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "vbls.h"
#include "vbls.hpp"

int vbls_ss_keygen(
	char *paramstr, size_t pstrlen,
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return vbls::ss::keygen( paramstr, pstrlen, pbuffer, plen, sbuffer, slen);
}

int vbls_ss_sign(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return vbls::ss::sign( paramstr, pstrlen, pbuffer, plen, sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int vbls_ss_verify(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return vbls::ss::verify( paramstr, pstrlen,
			pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int vbls_ibi_setup(
	char *paramstr, size_t pstrlen,
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return vbls::ibi::setup( paramstr, pstrlen, pbuffer, plen, sbuffer, slen);
}

int vbls_ibi_extract(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return vbls::ibi::extract( paramstr, pstrlen, pbuffer, plen, sbuffer, slen, mbuffer, mlen, obuffer, olen);
}


int vbls_ibi_prove(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	int port, const char *srv,
	int timeout
){
	return vbls::ibi::prove( paramstr, pstrlen, pbuffer, plen, mbuffer, mlen, obuffer, olen, port, srv, timeout );
}

int vbls_ibi_verify(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char **mbuffer, size_t *mlen,
	int port, int timeout
){
	return vbls::ibi::verify( paramstr, pstrlen, pbuffer, plen, mbuffer, mlen, port, timeout );
}

int vbls_ibi_verifytest(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return vbls::ibi::verifytest( paramstr, pstrlen,
			pbuffer, plen, mbuffer, mlen, obuffer, olen);
}
