/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/
This is a wrapper for the main file

based on the tutorial BLS pairings

ToraNova2019
*/

#include "bls_tight.h"
#include "bls_tight.hpp"

void bls_tight_keygen(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream){
	//bls_tight::keygen(paramstr, pstrlen, public_stream, secret_stream);
	bls_tight::opti::keygen(paramstr, pstrlen, public_stream, secret_stream);
	return;
}

void bls_tight_sign(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream,
	FILE *message_stream, FILE *sign_stream){
	//bls_tight::sign(paramstr, pstrlen, public_stream, secret_stream, message_stream, sign_stream);
	bls_tight::opti::sign(paramstr, pstrlen, public_stream, secret_stream, message_stream, sign_stream);
	return;
}

int bls_tight_verify(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *message_stream,
	FILE *sign_stream
){

	//return bls_tight::verify(paramstr, pstrlen, public_stream, message_stream, sign_stream);
	return bls_tight::opti::verify(paramstr, pstrlen, public_stream, message_stream, sign_stream);
}
