/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/
This is a wrapper for the main file

based on the tutorial BLS pairings

ToraNova2019
*/

#include "bls.h"
#include "bls.hpp"

int bls_ss_keygen(
	char *paramstr, size_t pstrlen,
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return bls::ss::keygen( paramstr, pstrlen, pbuffer, plen, sbuffer, slen);
}

int bls_ss_sign(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return bls::ss::sign( paramstr, pstrlen, pbuffer, plen, sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int bls_ss_verify(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return bls::ss::verify( paramstr, pstrlen,
			pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int bls_ibi_setup(
	char *paramstr, size_t pstrlen,
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return bls::ibi::setup( paramstr, pstrlen, pbuffer, plen, sbuffer, slen);
}

int bls_ibi_extract(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return bls::ibi::extract( paramstr, pstrlen, pbuffer, plen, sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int bls_ibi_verifytest(
	char *paramstr, size_t pstrlen,
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return bls::ibi::verifytest( paramstr, pstrlen,
			pbuffer, plen, mbuffer, mlen, obuffer, olen);
}
