/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/
This is a wrapper for the main file

based on the tutorial BLS pairings

ToraNova2019
*/

#include "ecc.h"
#include "ecc.hpp"

////internal paramgen function
//void ecc__paramgen(
//	char param_type,
//	int *opt0, int *opt1,
//	mpz_t *opt2, pbc_cm_ptr *opt3,
//	FILE *param_stream
//){
//	ecc::_paramgen( param_type, opt0, opt1, opt2, opt3, param_stream );
//	return;
//}

////auto paramgen 'a' param
//void ecc_aparam(
//	int rbit, int qbit,
//	FILE *param_stream
//){
//	ecc::aparam( rbit, qbit, param_stream );
//	return;
//}



void ecc_dparam(
	int d,
	FILE *param_stream
){
	ecc::dparam(d, param_stream);
	return;
}
