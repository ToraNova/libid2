/*
  test0, keygen test
  ToraNova 2019
  chia_jason96@live.com
*/
#include "bls.hpp"
#include "ptdebug.h"

#include "futil.h"

int main(int argc, char *argv[]){

	size_t n; unsigned int i;
	unsigned char *test = hexstr2uc("AF23021223", &n);

	if( !test ){ printf("Error!\n"); return 1;}
	for(i=0;i<n;i++){
		fprintf(stdout, "%02X", test[i]);
	}

	return 0;
}
