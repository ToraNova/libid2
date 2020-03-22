/*
  bls-ibi-kh test driver file
  ToraNova 2019
  chia_jason96@live.com
*/
#include "bls_ibi.h"
#include "ptdebug.h"
#include "ptdebug.h"

#include <time.h>

//#define str_paramfile 	"res/param160"
//#define str_paramfile 	"res/param224"
#define str_paramfile 	"res/param256"

#define str_publicfile 	"res/public"
#define str_secretfile 	"res/secret"
#define str_idfile 	"res/id"
#define str_uskfile 	"res/usk"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and verify
		FILE *paramfile = fopen( str_paramfile, "r");
		FILE *publicfile, *secretfile;
		FILE *idfile, *uskfile;
		char param[1024];
		size_t count = fread(param, 1, 1024, paramfile);
		log_info("Reading params from %s",str_paramfile);

		if( strcmp(argv[1], "setup") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			bls_ibi_tight_setup( param, count, publicfile, secretfile );

			fclose(publicfile);
			fclose(secretfile);
		}else if( strcmp(argv[1],"ext") == 0 ){
			publicfile = fopen( str_publicfile, "r");
			secretfile = fopen( str_secretfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "w");

			bls_ibi_tight_extract( param, count, publicfile, secretfile, idfile, uskfile );

			fclose(publicfile);
			fclose(secretfile);
			fclose(idfile);
			fclose(uskfile);

		}else if( strcmp(argv[1],"test") == 0){
			publicfile = fopen( str_publicfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");

			int rc = bls_ibi_tight_verifytest( param, count, publicfile, idfile, uskfile );
			if(rc==0){
				log_info("identification success");
			}else{
				log_info("identification fail");
			}

			fclose(publicfile);
			fclose(idfile);
			fclose(uskfile);

		}else if( strcmp(argv[1],"trial") == 0){
			//trial -- setup

			clock_t start, end;
			double cpu_time_used;
			unsigned int i;

			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			start = clock();
			for(i=0;i<30;i++){
				bls_ibi_tight_setup( param, count, publicfile, secretfile );
				rewind(publicfile);
				rewind(secretfile);
			}
			end = clock();
			bls_ibi_tight_setup( param, count, publicfile, secretfile );

			fclose(publicfile);
			fclose(secretfile);

			cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/30; //millis
			printf("SETUP (30) t: %f ms\n", cpu_time_used );

			publicfile = fopen( str_publicfile, "r");
			secretfile = fopen( str_secretfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "w");

			start = clock();
			for(i=0;i<100;i++){
				bls_ibi_tight_extract( param, count, publicfile, secretfile, idfile, uskfile );
				rewind(publicfile);
				rewind(secretfile);
				rewind(idfile);
				rewind(uskfile);
			}
			end = clock();
			bls_ibi_tight_extract( param, count, publicfile, secretfile, idfile, uskfile );

			fclose(uskfile);
			fclose(secretfile);

			rewind(publicfile);
			rewind(idfile);

			cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/100; //millis
			printf("EXTRACT (100) t: %f ms\n", cpu_time_used );

			uskfile = fopen( str_uskfile, "r");

			start = clock();
			for(i=0;i<100;i++){
				bls_ibi_tight_verifytest( param, count, publicfile, idfile, uskfile );
				rewind(publicfile);
				rewind(idfile);
				rewind(uskfile);
			}
			end = clock();
			cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000)/100; //millis
			printf("IDENTIFY (100) t: %f ms\n", cpu_time_used );

			fclose(uskfile);
			fclose(idfile);
			fclose(publicfile);

		}else{
			//echo an error
			log_err("Invalid mode %s, please specify either <setup|ext|test> !", argv[1]);
		}

		fclose(paramfile);
	}else{
		//echo an error
		log_err("Please specify mode <setup|ext|test> !");
	}

	return 0;
}
