/*
  test1, sign test
  ToraNova 2019
  chia_jason96@live.com
*/
#include "bls.h"
#include "ptdebug.h"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and sign
		FILE *publicfile = fopen("public", "r");
		FILE *secretfile = fopen("secret", "r");
		FILE *messagefile = fopen("message", "r");
		FILE *signfile = fopen("signature", "w");

		FILE *paramfile = fopen(argv[1], "r");

		char param[1024];
		size_t count = fread(param, 1, 1024, paramfile);
		log_info("Reading params from %s",argv[1]);
		bls_sign(param, count, publicfile,secretfile, messagefile,signfile);

		fclose(publicfile);
		fclose(secretfile);
		fclose(messagefile);
		fclose(signfile);
	}else{
		//echo an error
		log_err("Please specify param file!");
	}

	return 0;
}
