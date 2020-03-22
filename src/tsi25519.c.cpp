/*
 * An IBI scheme based off Ed25519
 * This is the wrapper to the functions defined under
 * the cpp version (wanted to use namespaces, but love c)
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
	return ts25519::keygen(pbuffer, plen, sbuffer, slen);
}

int ts25519_sign(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return ts25519::sign(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int ts25519_verify(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return ts25519::verify(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

int ti25519_setup(
	unsigned char **pbuffer, size_t *plen,
	unsigned char **sbuffer, size_t *slen
){
	return ti25519::setup(pbuffer, plen, sbuffer, slen);
}

int ti25519_extract(
	unsigned char *sbuffer, size_t slen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char **obuffer, size_t *olen
){
	return ti25519::extract(sbuffer, slen, mbuffer, mlen, obuffer, olen);
}

int ti25519_oclient(
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	int timeout
){
	return ti25519::oclient(mbuffer, mlen, obuffer, olen, srv, port, timeout);
}

int ti25519_oserver(
	unsigned char *pbuffer, size_t plen,
	unsigned char **mbuffer, size_t *mlen,
	int port, int timeout
){
	return ti25519::oserver(pbuffer, plen, mbuffer, mlen, port, timeout);
}

int ti25519_client(
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	int timeout
){
	return ti25519::client(mbuffer, mlen, obuffer, olen, srv, port, timeout);
}

void ti25519_server(
	unsigned char *pbuffer, size_t plen,
	void (*callback)(int, int, const unsigned char *, size_t),
	int port, int timeout, int maxcq
){
	ti25519::server(pbuffer, plen, callback, port, timeout, maxcq);
}

int ti25519_verifytest(
	unsigned char *pbuffer, size_t plen,
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen
){
	return ti25519::verifytest(pbuffer, plen, mbuffer, mlen, obuffer, olen);
}

//sample callbacks
void ti25519_sample_callback(int rc, int csock, const unsigned char *mbuf, size_t mlen){
	ti25519::sample_callback(rc,csock,mbuf,mlen);
	return;
}

//timing tests
//client
void ti25519_tclient(
	unsigned char *mbuffer, size_t mlen,
	unsigned char *obuffer, size_t olen,
	const char *srv, int port,
	int count
){
	ti25519::tclient(mbuffer,mlen,obuffer,olen,srv,port,count);
}

//server
void ti25519_tserver(
	unsigned char *pbuffer, size_t plen,
	int port, int count
){
	ti25519::tserver(pbuffer,plen,port,count);
}
