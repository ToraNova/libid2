/*
Boneh Lyn Shacham Signature IBI implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/

using bls_ibi_kh and bls_ibi_tight functions
ToraNova2019
*/

// declaration includes
#include "bls_ibi.h"
#include "bls_ibi.hpp"

void bls_ibi_kh_setup(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream
){
	bls_ibi_kh::setup( paramstr, pstrlen, public_stream, secret_stream );
	return;
}

void bls_ibi_kh_extract(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream,
	FILE *id_stream, FILE *usk_stream
){
	bls_ibi_kh::extract( paramstr, pstrlen, public_stream, secret_stream, id_stream, usk_stream );
	return;
}

int bls_ibi_kh_verifytest(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *id_stream,
	FILE *usk_stream
){
	return bls_ibi_kh::verifytest( paramstr, pstrlen, public_stream, id_stream, usk_stream );
}

void bls_ibi_tight_setup(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream
){
	bls_ibi_tight::setup( paramstr, pstrlen, public_stream, secret_stream );
	return;
}

void bls_ibi_tight_extract(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *secret_stream,
	FILE *id_stream, FILE *usk_stream
){
	bls_ibi_tight::extract( paramstr, pstrlen, public_stream, secret_stream, id_stream, usk_stream );
	return;
}

int bls_ibi_tight_verifytest(
	char *paramstr, size_t pstrlen,
	FILE *public_stream, FILE *id_stream,
	FILE *usk_stream
){
	return bls_ibi_tight::opti::verifytest( paramstr, pstrlen, public_stream, id_stream, usk_stream );
}
