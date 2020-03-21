/*
 * Final Year Project scheme
 * ToraNova 2019
 * chia_jason96@live.com
 * 25519 based Identity based identification scheme
*/
#include "id2.h"

#include <stdlib.h>
#include <time.h>
#define PORT 8051

#define str_publicfile 	"res/c25519/public"
#define str_secretfile 	"res/c25519/secret"
#define str_idfile 	"res/c25519/id"
#define str_uskfile 	"res/c25519/usk"

int main(int argc, char *argv[]){

	if(argc > 1){
		FILE *publicfile, *secretfile;
		FILE *idfile, *uskfile;
		if( strcmp(argv[1], "setup") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			unsigned char *pbuf, *sbuf;
			size_t plen, slen;

			ti25519_setup( &pbuf, &plen, &sbuf, &slen);

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

			ti25519_extract( sbuf, slen, mbuf, mlen, &obuf, &olen);
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

			int rc = ti25519_verifytest( pbuf, plen, mbuf, mlen, obuf, olen);
			if(rc==0){
				printf("identification success\n");
			}else{
				printf("identification fail\n");
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
				rc = ti25519_prove( mbuf, mlen, obuf, olen, PORT, argv[2],10);
			}else{
				rc = ti25519_prove( mbuf, mlen, obuf, olen, PORT, "127.0.0.1",10);
			}
			if(rc==0){
				printf("prove success\n");
			}else{
				printf("prove fail\n");
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

			int rc = ti25519_verify( pbuf, plen, &mbuf, &mlen, PORT, 10);
			debug("rc:%d",rc);
			if(rc==0){
				printf("verify success [%s]\n", mbuf);
			}else{
				printf("verify fail [%s]\n", mbuf);
			}

			fclose(publicfile);
			free(pbuf);
			free(mbuf);

		}else{
			//echo an error
			lerror("Invalid mode %s, please specify either <setup|ext|prove|verify|test> !\n", argv[1]);
		}
	}else{
		//echo an error
		lerror("Insufficient args, please specify either <setup|ext|prove|verify|test> !\n");
	}

	return 0;
}
