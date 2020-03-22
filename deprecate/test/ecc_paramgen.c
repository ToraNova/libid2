/*
  test, paramgen test
  ToraNova 2019
  chia_jason96@live.com
*/
#include "ecc.h"
#include "ptdebug.h"

int main(int argc, char *argv[]){

	//open file stream for writing
	FILE *paramfile0 = fopen("d192", "w");
	FILE *paramfile1 = fopen("d256", "w");
	FILE *paramfile2 = fopen("d359", "w");
	FILE *paramfile3 = fopen("d407", "w");
	FILE *paramfile4 = fopen("d522", "w");
	FILE *paramfile5 = fopen("d677", "w");
	FILE *paramfile6 = fopen("d1357", "w");

	/* creates the parameters
	 * https://crypto.stanford.edu/pbc/mnt.html
	 * D		q(base)		r
	 * 1835683,	193,		180 (DLOG->1158bits)
	 * 249563,	252,		234 (DLOG->1512bits)
	 * 481843,	359,		356 (DLOG->2154bits)
	 * 238859,	407,		383 (DLOG->2442bits)
	 * 311387,	522,		514 (DLOG->3132bits)
	 * 594739,	677,		650 (DLOG->4062bits)
	 * 972483,	1357,		1357(DLOG->8142bits)
	 */
	ecc_dparam( 1835683, paramfile0);
	ecc_dparam( 249563, paramfile1);
	ecc_dparam( 481843, paramfile2 );
	ecc_dparam( 238859, paramfile3 );
	ecc_dparam( 311387, paramfile4 );
	ecc_dparam( 594739, paramfile5 );
	ecc_dparam( 972483, paramfile6 );

	//write to file
	fclose(paramfile0);
	fclose(paramfile1);
	fclose(paramfile2);
	fclose(paramfile3);
	fclose(paramfile4);
	fclose(paramfile5);
	fclose(paramfile6);
	return 0;
}
