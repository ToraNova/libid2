/*
  bls-ibi-new test driver file
  Final Year Project scheme
  ToraNova 2019
  chia_jason96@live.com
*/
#include "id2.h"

#include <time.h>
#include <cstdlib>
#define PORT 8051

//#define str_paramfile 	"params/d192.param" // 0.3189ms; 0.02286ms; 0.2697ms
//#define str_paramfile 	"params/d256.param" // 0.4392ms; 0.03433ms; 0.3528ms
#define str_paramfile 	"params/d359.param" // 0.8802ms; 0.06141ms; 0.7193ms
//#define str_paramfile 	"params/d407.param" // 1.0784ms; 0.08740ms; 0.9307ms
//#define str_paramfile 	"params/d522.param" // 1.8700ms; 0.1404ms; 1.6583ms
//#define str_paramfile 	"params/d677.param" // 3.0245ms; 0.2311ms; 2.7238ms
//#define str_paramfile 	"params/d1357.param" // 15.13ms; 0.9767ms; 14.98ms

#define str_publicfile 	"res/vblsibi/public"
#define str_secretfile 	"res/vblsibi/secret"
#define str_idfile 	"res/vblsibi/id"
#define str_uskfile 	"res/vblsibi/usk"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and verify
		FILE *paramfile = fopen( str_paramfile, "r");
		FILE *publicfile, *secretfile;
		FILE *idfile, *uskfile;
		char param[PARAM_BUF_SZ];
		size_t count = fread(param, 1, PARAM_BUF_SZ, paramfile);
		log_info("Reading params from %s",str_paramfile);

		if( strcmp(argv[1], "setup") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			unsigned char *pbuf, *sbuf;
			size_t plen, slen;

			vbls_ibi_setup( param, count, &pbuf, &plen, &sbuf, &slen);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( strcmp(argv[1],"ext") == 0 ){
			publicfile = fopen( str_publicfile, "r");
			secretfile = fopen( str_secretfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "w");

			unsigned char *pbuf, *sbuf, *obuf, *mbuf;
			size_t plen, slen, mlen, olen;

			pbuf = read_b64( publicfile, &plen );
			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( idfile, &mlen );


			vbls_ibi_extract( param, count, pbuf, plen, sbuf, slen, mbuf, mlen, &obuf, &olen);

			write_b64( uskfile, obuf, olen );

			fclose(publicfile);
			fclose(secretfile);
			fclose(idfile);
			fclose(uskfile);

			free(pbuf);
			free(sbuf);
			free(mbuf);
			free(obuf);

		}else if( strcmp(argv[1],"test") == 0){
			publicfile = fopen( str_publicfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");

			unsigned char *pbuf, *obuf, *mbuf;
			size_t plen, mlen, olen;

			pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			int rc = vbls_ibi_verifytest( param, count, pbuf, plen, mbuf, mlen, obuf, olen);
			if(rc==0){
				log_info("identification success");
			}else{
				log_info("identification fail");
			}

			fclose(publicfile);
			fclose(idfile);
			fclose(uskfile);

			free(pbuf);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[1],"prove") == 0){
			int rc;
			publicfile = fopen( str_publicfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			unsigned char *pbuf, *obuf, *mbuf;
			size_t plen, mlen, olen;

			pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			if( argc > 2 ){
				rc = vbls_ibi_prove( param, count, pbuf, plen, mbuf, mlen, obuf, olen, PORT, argv[2],10);
			}else{
				rc = vbls_ibi_prove( param, count, pbuf, plen, mbuf, mlen, obuf, olen, PORT, "127.0.0.1",10);
			}
			if(rc==0){
				log_info("prove success");
			}else{
				log_info("prove fail");
			}

			fclose(publicfile);
			fclose(idfile);
			fclose(uskfile);
			free(pbuf);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[1],"verify") == 0){
			publicfile = fopen( str_publicfile, "r");
			int rc;
			unsigned char *pbuf, *mbuf;
			size_t plen, mlen;
			pbuf = read_b64( publicfile, &plen );

			rc = vbls_ibi_verify( param, count, pbuf, plen, &mbuf, &mlen, PORT, 10);
			if(rc==0){
				log_info("verify success [%s]", mbuf);
			}else{
				log_info("verify fail [%s]", mbuf);
			}

			fclose(publicfile);
			free(pbuf);
			free(mbuf);

		}else{
			//echo an error
			log_err("Invalid mode %s, please specify either <setup|ext|prove|verify|test> !", argv[1]);
		}

		fclose(paramfile);
	}else{
		//echo an error
		log_err("Insufficient args, please specify either <setup|ext|prove|verify|test> !");
	}

	return 0;
}
