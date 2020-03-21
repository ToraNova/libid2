/*
 * TNC signature test
  Final Year Project scheme
  ToraNova 2019
  chia_jason96@live.com
*/
#include "id2.h"

#include <time.h>
#include <stdlib.h>
#define PORT 8051

#define str_publicfile 	"res/c25519/public"
#define str_secretfile 	"res/c25519/secret"
#define str_messagefile "res/c25519/id"
#define str_signfile 	"res/c25519/usk"

int main(int argc, char *argv[]){
	int rc;

	if(argc > 1){
		//read param file and verify
		FILE *publicfile, *secretfile;
		FILE *messagefile, *signfile;

		if( strcmp(argv[1], "gen") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");

			unsigned char *pbuf, *sbuf;
			size_t plen, slen;

			rc = ts25519_keygen( &pbuf, &plen, &sbuf, &slen);
			if(rc != 0)lerror("Keygen Error\n");

			//output as asn1 der PEM
			//e25519_asn1_der_out( publicfile, pbuf, plen, TYPE_PUBLIC);
			//e25519_asn1_der_out( secretfile, sbuf, slen, TYPE_SECRET);

			//output raw base64
			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( strcmp(argv[1],"sign") == 0 ){

			secretfile = fopen( str_secretfile, "r");
			messagefile =  fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "w");

			unsigned char *sbuf, *obuf, *mbuf;
			size_t slen, mlen, olen;

			//read as asn1 der PEM
			//sbuf = e25519_asn1_der_in( secretfile, &slen, TYPE_SECRET );

			//raw base64
			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( messagefile, &mlen );

			rc = ts25519_sign(sbuf, slen, mbuf, mlen, &obuf, &olen);
			if(rc != 0)lerror("Sign Error\n");

			write_b64( signfile, obuf, olen );

			fclose(secretfile);
			fclose(messagefile);
			fclose(signfile);

			free(sbuf);
			free(mbuf);
			free(obuf);

		}else if( strcmp(argv[1],"verify") == 0){
			publicfile = fopen( str_publicfile, "r");
			messagefile = fopen( str_messagefile, "r");
			signfile = fopen( str_signfile, "r");

			unsigned char *pbuf, *obuf, *mbuf;
			size_t plen, mlen, olen;

			//read as asn1 DER PEM
			//pbuf = e25519_asn1_der_in( publicfile, &plen, TYPE_PUBLIC );

			//raw base64
			pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( signfile, &olen );
			mbuf = (unsigned char *)fileread( messagefile, &mlen );

			rc = ts25519_verify( pbuf, plen, mbuf, mlen, obuf, olen);
			if(rc==0){
				printf("signature valid\n");
			}else{
				printf("signature invalid\n");
			}

			fclose(publicfile);
			fclose(messagefile);
			fclose(signfile);

			free(pbuf);
			free(obuf);
			free(mbuf);
		}else{
			//echo an error
			lerror("Invalid mode %s, please specify either <gen|sign|verify> !\n", argv[1]);
		}

	}else{
		//echo an error
		lerror("Please specify mode <gen|sign|verify> !\n");
	}

	return 0;
}
