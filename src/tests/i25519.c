/*
 * Final Year Project scheme
 * ToraNova 2019
 * chia_jason96@live.com
 * 25519 based Identity based identification scheme
*/
#include "../id2.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#define PORT 8051

#define str_publicfile 	"public"
#define str_secretfile 	"secret"
#define str_idfile 	"userid.txt"
#define str_uskfile 	"user.key"

#define int_testcnt 100
#define int_waittim 5

int main(int argc, char *argv[]){
	int rc;
	FILE *publicfile, *secretfile;
	FILE *idfile, *uskfile;
	unsigned char *pbuf, *sbuf, *obuf, *mbuf;
	size_t plen, slen, mlen, olen;

	clock_t start, end;
	//unsigned int i;
	double cpu_time_use = 0;

	if(argc > 1){
		if( strcmp(argv[1], "setup") == 0 ){

			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");
			if( secretfile == NULL || publicfile == NULL ){
				lerror("Unable to write to %s/%s\n",str_secretfile,str_publicfile);
				return 1;
			}

			start = clock();
			rc = ti25519_setup( &pbuf, &plen, &sbuf, &slen);
			end = clock();
			cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
			if(rc != 0){ lerror("Setup Error\n"); }
			printf("setup took %.4f ms\n", cpu_time_use);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( strcmp(argv[1],"ext") == 0 ){
			secretfile = fopen( str_secretfile, "r");
			idfile = fopen( str_idfile, "r");
			if( secretfile == NULL || idfile == NULL ){
				lerror("Missing %s or %s\n",str_secretfile,str_idfile);
				return 1;
			}
			uskfile = fopen( str_uskfile, "w");
			if( uskfile == NULL ){
				lerror("Unable to write %s\n",str_uskfile);
				return 1;
			}

			sbuf = read_b64( secretfile, &slen );
			mbuf = (unsigned char *)fileread( idfile, &mlen );

			start = clock();
			rc = ti25519_extract( sbuf, slen, mbuf, mlen, &obuf, &olen);
			end = clock();
			cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
			if(rc != 0){ lerror("Extract Error\n"); }
			printf("extract took %.4f ms\n", cpu_time_use);

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
			if( publicfile == NULL || idfile == NULL || uskfile == NULL ){
				lerror("Missing %s/%s/%s\n",str_publicfile,str_idfile,str_uskfile);
				return 1;
			}

			pbuf = read_b64( publicfile, &plen );
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			rc = ti25519_verifytest( pbuf, plen, mbuf, mlen, obuf, olen);
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
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			if( idfile == NULL || uskfile == NULL ){
				lerror("Missing %s/%s\n",str_idfile,str_uskfile);
				return 1;
			}
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			if( argc > 2 ){
				rc = ti25519_oclient( mbuf, mlen, obuf, olen, argv[2], PORT, 60);
			}else{
				rc = ti25519_oclient( mbuf, mlen, obuf, olen, "127.0.0.1", PORT, 60);
			}
			if(rc==0){
				printf("prove success [%s] 0x%02x\n", mbuf, rc);
			}else{
				printf("prove fail [%s] 0x%02x\n", mbuf, rc);
			}

			fclose(idfile);
			fclose(uskfile);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[1],"verify") == 0){
			//ONE shot verify
			publicfile = fopen( str_publicfile, "r");
			if( publicfile == NULL ){
				lerror("Missing %s\n",str_publicfile);
				return 1;
			}
			pbuf = read_b64( publicfile, &plen );

			rc = ti25519_oserver( pbuf, plen, &mbuf, &mlen, PORT, 60);
			if(rc==0){
				printf("verify success [%s] 0x%02x\n", mbuf, rc);
			}else{
				printf("verify fail [%s] 0x%02x\n", mbuf, rc);
			}

			fclose(publicfile);
			free(pbuf);
			free(mbuf);

		}else if( strcmp(argv[1],"client") == 0){

			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			if( idfile == NULL || uskfile == NULL ){
				lerror("Missing %s/%s\n",str_idfile,str_uskfile);
				return 1;
			}
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );
			int csock;

			if( argc > 2 ){
				csock = ti25519_client( mbuf, mlen, obuf, olen, argv[2], PORT, 60);
			}else{
				csock = ti25519_oclient( mbuf, mlen, obuf, olen, "127.0.0.1", PORT, 60);
			}
			if(csock != -1){
				//authentication success
				rc = 1;
				printf("prove success [%s] 0x%02x\n", mbuf, rc);
				close(csock); //close it or do something else with it
			}else{
				rc = 0;
				printf("prove fail [%s] 0x%02x\n", mbuf, rc);
			}

			fclose(idfile);
			fclose(uskfile);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[1],"server") == 0 ){
			//persistent verify
			publicfile = fopen( str_publicfile, "r");
			if( publicfile == NULL ){
				lerror("Missing %s\n",str_publicfile);
				return 1;
			}
			pbuf = read_b64( publicfile, &plen );

			ti25519_server( pbuf, plen, ti25519_sample_callback, PORT, 10, 5);
			//don't expect to leave this place

		}else if( strcmp(argv[1],"runtest") == 0 ){
			if(argc > 2){
				publicfile = fopen( str_publicfile, "r");
				idfile = fopen( str_idfile, "r");
				uskfile = fopen( str_uskfile, "r");
				obuf = read_b64( uskfile, &olen );
				pbuf = read_b64( publicfile, &plen );
				mbuf = (unsigned char *) fileread( idfile, &mlen );
				unsigned int count = 10000;

				if( strcmp(argv[2],"prove") == 0 ){
					if(argc > 3){
						ti25519_tclient( mbuf, mlen, obuf, olen, argv[3], PORT, count );
					}else{
						ti25519_tclient( mbuf, mlen, obuf, olen, "127.0.0.1", PORT, count );
					}
				}else if( strcmp(argv[2],"verify") == 0){
					//verifies for 100 times
					ti25519_tserver( pbuf, plen, PORT, count );
				}
			}else{
				lerror("Please specify either <prove|verify> for runtest !\n");
				return 1;
			}
		}else{
			//echo an error
			lerror("Invalid mode %s, please specify either <setup|ext|prove|verify|server|client|test|runtest> !\n", argv[1]);
			return 1;
		}

		printf("i25519 run OK.\n");
		return 0;
	}else{
		//echo an error
		lerror("Insufficient args, please specify either <setup|ext|prove|verify|server|client|test|runtest> !\n");
		return 1;
	}

}
