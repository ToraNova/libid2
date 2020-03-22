/*
Boneh Lyn Shacham Signature implementation
using pbc library from stanford
https://crypto.stanford.edu/pbc/

based on the tutorial BLS pairings
ToraNova2019
*/

// declaration includes
#include "ecc.hpp"
#include "ptdebug.h"

// implementation includes
#include <pbc/pbc.h> //for the pairing based crypto magic
#include <pbc/pbc_utils.h>  // for UNUSED_VAR
#include <gmp.h> //gnu multiprecision

// standard lib
#include <string>
#include <cstdlib>
#include <cstdio>

// default param
#define APARAM_RBIT 160
#define APARAM_QBIT 512

using namespace std;
namespace ecc
{
	// Generate MNT curve(s) for a given D.
	int _generate(pbc_cm_t cm, void *data) {
	  pbc_param_t param;
	  pbc_info("gendparam: computing Hilbert polynomial and finding roots...");
	  pbc_param_init_d_gen(param, cm);
	  pbc_info("gendparam: bits in q = %zu\n", mpz_sizeinbase(cm->q, 2));
	  pbc_param_out_str( (FILE *)data, param);
	  pbc_param_clear(param);
	  return 1;
	}

	void dparam( int D, FILE *param_stream
	){
		pbc_info("Using D = %d\n", D);
		if (!pbc_cm_search_d(_generate, param_stream, D, 500)) {
			pbc_die("no suitable curves for this D");
		}
		return;
	}
}
