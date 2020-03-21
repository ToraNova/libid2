/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
*/

#include "tsi25519.h"
#include "tsi25519.hpp"

//TS - tight signature
//TI - tight identity based identification

int ts25519_keygen(
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return tsi25519::ss::keygen(pbuffer, plen, sbuffer, slen);
}

int ts25519_sign(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return tsi25519::ss::sign(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int ts25519_verify(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return tsi25519::ss::verify(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int ti25519_setup(
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return tsi25519::ibi::setup(pbuffer, plen, sbuffer, slen);
}

int ti25519_extract(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return tsi25519::ibi::extract(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int ti25519_prove(
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	int port, const char *srv,
	int timeout
){
	return tsi25519::ibi::prove(mbuffer, mlen, obuffer, olen, port, srv, timeout);
}

int ti25519_verify(
	unsigned char *pbuffer, size_t plen,
	unsigned char **mbuffer, size_t *mlen,
	int port, int timeout
){
	return tsi25519::ibi::verify(pbuffer, plen, mbuffer, mlen, port, timeout);
}

int ti25519_verifytest(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return tsi25519::ibi::verifytest(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}
