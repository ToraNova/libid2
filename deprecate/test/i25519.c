/*
 * Final Year Project scheme
 * ToraNova 2019
 * chia_jason96@live.com
 * EdDSA Identity based identification scheme
*/
#include "id2.h"

#include <cstdlib>
#include <time.h>
#define PORT 8051

#define str_publicfile 	"res/c25519/public"
#define str_secretfile 	"res/c25519/secret"
#define str_idfile 	"res/c25519/id"
#define str_uskfile 	"res/c25519/signature"

int main(int argc, char *argv[]){

	if(argc > 1){
		FILE *publicfile, *secretfile;
		FILE *idfile, *uskfile;
		if( strcmp(argv[1], "setup") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			unsigned char *pbuf, *sbuf;
			size_t plen, slen;

			i25519_setup( &pbuf, &plen, &sbuf, &slen);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( strcmp(argv[1],"ext") == 0 ){
			secretfile = fopen( str_secretfile, "r");
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "w");

			unsigned char *sbuf, *obuf, *mbuf;
			size_t slen, mlen, olen;

			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( idfile, &mlen );

			i25519_extract( sbuf, slen, mbuf, mlen, &obuf, &olen);
			write_b64( uskfile, obuf, olen );

			fclose(secretfile);
			fclose(idfile);
			fclose(uskfile);

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

			int rc = i25519_verifytest( pbuf, plen, mbuf, mlen, obuf, olen);
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
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			unsigned char *obuf, *mbuf;
			size_t mlen, olen;

			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			if( argc > 2 ){
				rc = i25519_prove( mbuf, mlen, obuf, olen, PORT, argv[2],10);
			}else{
				rc = i25519_prove( mbuf, mlen, obuf, olen, PORT, "127.0.0.1",10);
			}
			if(rc==0){
				log_info("prove success");
			}else{
				log_info("prove fail");
			}

			fclose(idfile);
			fclose(uskfile);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[1],"verify") == 0){
			publicfile = fopen( str_publicfile, "r");
			unsigned char *pbuf, *mbuf;
			size_t plen, mlen;
			pbuf = read_b64( publicfile, &plen );

			int rc = i25519_verify( pbuf, plen, &mbuf, &mlen, PORT, 10);
			debug("rc:%d",rc);
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
	}else{
		//echo an error
		log_err("Insufficient args, please specify either <setup|ext|prove|verify|test> !");
	}

	return 0;
}
