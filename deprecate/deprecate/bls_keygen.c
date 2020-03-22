/*
  test0, keygen test
  ToraNova 2019
  chia_jason96@live.com
*/
#include "bls.h"
#include "ptdebug.h"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and keygen
		FILE *publicfile = fopen("public", "w");
		FILE *secretfile = fopen("secret", "w");
		FILE *paramfile = fopen(argv[1], "r");
		char param[1024];
		size_t count = fread(param, 1, 1024, paramfile);
		log_info("Reading params from %s",argv[1]);
		bls_keygen(param, count, publicfile,secretfile);

		fclose(publicfile);
		fclose(secretfile);
	}else{
		//echo an error
		log_err("Please specify param file!");
	}

	return 0;
}
