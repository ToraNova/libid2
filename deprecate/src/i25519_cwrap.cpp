/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
*/

#include "i25519.h"
#include "i25519.hpp"

int e25519_keygen(
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return c25519::ss::keygen(pbuffer, plen, sbuffer, slen);
}

int e25519_sign(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return c25519::ss::sign(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int e25519_verify(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return c25519::ss::verify(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int i25519_setup(
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return c25519::ibi::setup(pbuffer, plen, sbuffer, slen);
}

int i25519_extract(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return c25519::ibi::extract(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int i25519_prove(
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	int port, const char *srv,
	int timeout
){
	return c25519::ibi::prove(mbuffer, mlen, obuffer, olen, port, srv, timeout);
}

int i25519_verify(
	unsigned char *pbuffer, size_t plen,
	unsigned char **mbuffer, size_t *mlen,
	int port, int timeout
){
	return c25519::ibi::verify(pbuffer, plen, mbuffer, mlen, port, timeout);
}

int i25519_verifytest(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return c25519::ibi::verifytest(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}
