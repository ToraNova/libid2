/*
  vBLS signature scheme test driver file
  ToraNova 2019
  chia_jason96@live.com
*/
#include "id2.h"

#define str_paramfile 	"params/d359.param"

#define str_publicfile 	"res/vbls/public"
#define str_secretfile 	"res/vbls/secret"
#define str_messagefile "res/vbls/message"
#define str_signfile 	"res/vbls/signature"

int main(int argc, char *argv[]){

	if(argc > 1){
		//read param file and verify
		FILE *paramfile = fopen( str_paramfile, "r");
		FILE *publicfile, *secretfile;
		FILE *messagefile, *signfile;
		char param[PARAM_BUF_SZ];
		size_t count = fread(param, 1, PARAM_BUF_SZ, paramfile);
		log_info("Reading params from %s",str_paramfile);

		if( strcmp(argv[1], "gen") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			unsigned char *pbuf, *sbuf;
			size_t plen, slen;

			vbls_ss_keygen( param, count, &pbuf, &plen, &sbuf, &slen);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( strcmp(argv[1],"sign") == 0 ){
			publicfile = fopen( str_publicfile, "r");
			secretfile = fopen( str_secretfile, "r");
			messagefile =  fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "w");

			unsigned char *pbuf, *sbuf, *obuf, *mbuf;
			size_t plen, slen, mlen, olen;

			pbuf = read_b64( publicfile, &plen );
			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( messagefile, &mlen );

			vbls_ss_sign( param, count, pbuf, plen, sbuf, slen, mbuf, mlen, &obuf, &olen);

			write_b64( signfile, obuf, olen );

			fclose(publicfile);
			fclose(secretfile);
			fclose(messagefile);
			fclose(signfile);

			free(pbuf);
			free(sbuf);
			free(mbuf);
			free(obuf);

		}else if( strcmp(argv[1],"verify") == 0){
			publicfile = fopen( str_publicfile, "r");
			messagefile = fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "r");

			unsigned char *pbuf, *obuf, *mbuf;
			size_t plen, mlen, olen;

			pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( signfile, &olen );
			mbuf = (unsigned char *)fileread( messagefile, &mlen );

			int rc = vbls_ss_verify( param, count, pbuf, plen, mbuf, mlen, obuf, olen);
			if(rc==0){
				log_info("signature valid");
			}else{
				log_info("signature invalid");
			}

			fclose(publicfile);
			fclose(messagefile);
			fclose(signfile);

			free(pbuf);
			free(obuf);
			free(mbuf);


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
