/*
  BLS signature scheme test driver file
  ToraNova 2019
  chia_jason96@live.com
*/
#include "bls_tight.h"
#include "ptdebug.h"

#define str_paramfile 	"res/param160"

#define str_publicfile 	"res/bls/public"
#define str_secretfile 	"res/bls/secret"
#define str_messagefile "res/bls/message"
#define str_signfile 	"res/bls/signature"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and verify
		FILE *paramfile = fopen( str_paramfile, "r");
		FILE *publicfile, *secretfile;
		FILE *messagefile, *signfile;
		char param[1024];
		size_t count = fread(param, 1, 1024, paramfile);
		log_info("Reading params from %s",str_paramfile);

		if( strcmp(argv[1], "gen") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			bls_tight_keygen( param, count, publicfile, secretfile );

			fclose(publicfile);
			fclose(secretfile);
		}else if( strcmp(argv[1],"sign") == 0 ){
			publicfile = fopen( str_publicfile, "r");
			secretfile = fopen( str_secretfile, "r");
			messagefile =  fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "w");

			bls_tight_sign( param, count, publicfile, secretfile, messagefile, signfile );

			fclose(publicfile);
			fclose(secretfile);
			fclose(messagefile);
			fclose(signfile);

		}else if( strcmp(argv[1],"verify") == 0){
			publicfile = fopen( str_publicfile, "r");
			messagefile = fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "r");

			int rc = bls_tight_verify( param, count, publicfile, messagefile, signfile );
			if(rc==0){
				log_info("signature valid");
			}else{
				log_info("signature invalid");
			}

			fclose(publicfile);
			fclose(messagefile);
			fclose(signfile);

		}else{
			//echo an error
			log_err("Invalid mode %s, please specify either <gen|sign|verify> !", argv[1]);
		}

		fclose(paramfile);
	}else{
		//echo an error
		log_err("Please specify mode <gen|sign|verify> !");
	}

	return 0;
}
