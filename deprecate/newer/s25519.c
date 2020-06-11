/*
 * TNC signature test
  Final Year Project scheme
  ToraNova 2019
  chia_jason96@live.com
*/
#include "../id2.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#define PORT 8051

#define str_publicfile 	"public"
#define str_secretfile 	"secret"
#define str_messagefile "message.txt"
#define str_signfile 	"signature.b"

#define int_testcnt 1000
#define str_teststr "test"

int main(int argc, char *argv[]){
	int rc;
	FILE *publicfile, *secretfile;
	FILE *messagefile, *signfile;
	unsigned char *pbuf, *sbuf, *obuf, *mbuf;
	size_t plen, slen, mlen, olen;

	if(argc > 1){
		if( strcmp(argv[1], "gen") == 0 ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");
			if( secretfile == NULL || publicfile == NULL ){
				lerror("Unable to write to %s/%s\n",str_secretfile,str_publicfile);
				return 1;
			}

			rc = ts25519_keygen( &pbuf, &plen, &sbuf, &slen);
			if(rc != 0){ lerror("Keygen Error\n"); }

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
			if( secretfile == NULL || messagefile == NULL ){
				lerror("Missing %s or %s\n",str_secretfile,str_messagefile);
				return 1;
			}
			signfile = fopen( str_signfile, "w");
			if( signfile == NULL ){
				lerror("Unable to write %s\n",str_signfile);
				return 1;
			}

			//read as asn1 der PEM
			//sbuf = e25519_asn1_der_in( secretfile, &slen, TYPE_SECRET );

			//raw base64
			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( messagefile, &mlen );

			rc = ts25519_sign(sbuf, slen, mbuf, mlen, &obuf, &olen);
			if(rc != 0){ lerror("Sign Error\n");}

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
			if( publicfile == NULL || messagefile == NULL || signfile == NULL ){
				lerror("Missing %s/%s/%s\n",str_publicfile,str_messagefile,str_signfile);
				return 1;
			}


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
		}else if( strcmp(argv[1],"runtest") == 0){
			unsigned char mbuf[] = str_teststr;
			unsigned int i;
			clock_t start, end;
			double cpu_time_use0, cpu_time_use1, cpu_time_use2;

			start = clock();
			for( i = 0 ; i < int_testcnt ; i++){
				ts25519_keygen( &pbuf, &plen, &sbuf, &slen);
			}
			end = clock();
			//millis averaged
			cpu_time_use0 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;

			start = clock();
			for( i = 0 ; i < int_testcnt ; i++){
				ts25519_sign(sbuf, slen, mbuf, strlen(mbuf), &obuf, &olen);
			}
			end = clock();
			//millis averaged
			cpu_time_use1 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;

			start = clock();
			for( i = 0 ; i < int_testcnt ; i++){
				rc = ts25519_verify( pbuf, plen, mbuf, strlen(mbuf), obuf, olen);
			}
			end = clock();
			//millis averaged
			cpu_time_use2 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;
			printf("Final res: %d\n", rc);
			printf("keygen %d/: %f ms\n", int_testcnt, cpu_time_use0 );
			printf("sign /%d: %f ms\n", int_testcnt, cpu_time_use1 );
			printf("verify /%d: %f ms\n", int_testcnt, cpu_time_use2 );

			free(sbuf); free(pbuf); free(obuf);
		}else{
			//echo an error
			lerror("Invalid mode %s, please specify either <gen|sign|verify|runtest> !\n", argv[1]);
			return 1;
		}
		printf("s25519 run OK.\n");
		return 0; //OK
	}else{
		//echo an error
		lerror("Please specify mode <gen|sign|verify|runtest> !\n");
		return 1;
	}
}
