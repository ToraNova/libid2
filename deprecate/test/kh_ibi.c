/*
  bls-ibi-kh test driver file
  ToraNova 2019
  chia_jason96@live.com
*/
#include "id2.h"

#include <time.h>
#include <cstdlib>

//#define str_paramfile 	"params/d192.param" // 0.2635ms; 0.02136ms; 0.2695ms
//#define str_paramfile 	"params/d256.param" // 0.3529ms; 0.03157ms; 0.3502ms
#define str_paramfile 	"params/d359.param" // 0.7103ms; 0.05930ms; 0.7185ms
//#define str_paramfile 	"params/d407.param" // 0.8678ms; 0.08130ms; 0.9269ms
//#define str_paramfile 	"params/d522.param" // 1.522ms; 0.1323ms; 1.653ms
//#define str_paramfile 	"params/d677.param" // 2.440ms; 0.2242ms; 2.717ms
//#define str_paramfile 	"params/d1357.param" // 12.273ms; 0.9747ms; 14.91ms

#define str_publicfile 	"res/khblsibi/public"
#define str_secretfile 	"res/khblsibi/secret"
#define str_idfile 	"res/khblsibi/id"
#define str_uskfile 	"res/khblsibi/usk"

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

			bls_ibi_setup( param, count, &pbuf, &plen, &sbuf, &slen);

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

			bls_ibi_extract( param, count, pbuf, plen, sbuf, slen, mbuf, mlen, &obuf, &olen);

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

			int rc = bls_ibi_verifytest( param, count, pbuf, plen, mbuf, mlen, obuf, olen);
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

		}else if( strcmp(argv[1],"trial") == 0){
			//trial -- setup

			//TODO: please fix this

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
