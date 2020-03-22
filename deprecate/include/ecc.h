/*
  Wrapper for bls.hpp
  Made for paircrypt

  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _ECC_H_
#define _ECC_H_

#include <pbc/pbc.h>

#ifdef __cplusplus
extern "C"{
#endif

	/*
	 * BLS param gen
	 * Generates A parameter
	 * param_type -> types of param
	 * param_stream -> the param file to be outputted
	 * a -> a type parameters (opt0 - qbit, opt1 - rbit)
	 * A -> a1 type parameters (opt0 - qbit, opt1 - rbit)
	 */
	//void ecc__paramgen(
	//	char param_type,
	//	int *opt0, int *opt1,
	//	mpz_t *opt2, pbc_cm_ptr *opt3,
	//	FILE *param_stream
	//);

	/*
	 * Generates a 'a' parameter
	 * for eliptic curve crypto
	 * rbit -> group order bitlength
	 * qbit -> base field order bitlength
	 * param_stream -> output file/stdout stream
	 */
	// ON HOLD FOR NOW, type-1 pairings are broken
	//void ecc_aparam(
	//	int rbit, int qbit,
	//	FILE *param_stream
	//);

	/* https://crypto.stanford.edu/pbc/manual/ch05s01.html
	 * https://crypto.stanford.edu/pbc/manual/ch08s06.html
	 * Generates a type 'd' parameter
	 * type: dn
	 * base field: n
	 * k = 6
	 * DLOG security = 6n
	 * Good for cryptosystems when group elements must be as short as possible.
	 * Uses MNT method to generate curves.
	 * INPUT -> d (discriminant)
	 * https://crypto.stanford.edu/pbc/mnt.html
	 * D		q(base)		r
	 * 3371809, 	192,		DLOG->1152
	 * 56415963, 	256,		DLOG->1536
	 * 481843,	359,		356 (DLOG->2154bits)
	 * 238859,	407,		383 (DLOG->2442bits)
	 * 311387,	522,		514 (DLOG->3132bits)
	 * 594739,	677,		650 (DLOG->4062bits)
	 * 972483,	1357,		1357(DLOG->8142bits)
	 */
	void ecc_dparam(
		int d,
		FILE *param_stream
	);



#ifdef __cplusplus
}
#endif

#endif
