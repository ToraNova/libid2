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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define PORT 8051

#define str_publicfile 	"public"
#define str_secretfile 	"secret"
#define str_idfile 	"id.txt"
#define str_uskfile 	"user.key"

#define int_testcnt 10000
#define int_waittim 5
#define str_teststr "Hello Identity based identification!"

//sample implementation of a callback function
void sample_callback(int rc, int csock, const unsigned char *mbuffer, size_t mlen){
	if(rc==0){
		printf("verify success [%s] 0x%02x\n", mbuffer, rc);
	}else{
		printf("verify fail [%s] 0x%02x\n", mbuffer, rc);
	}
	return;
}

int main(int argc, char *argv[]){
	int rc; unsigned int algo;
	FILE *publicfile, *secretfile;
	FILE *idfile, *uskfile;
	unsigned char *pbuf, *sbuf, *obuf, *mbuf;
	size_t plen, slen, mlen, olen;
	clock_t start, end;
	unsigned int i;
	double cpu_time_use0, cpu_time_use1, cpu_time_use2;

	if(argc > 2){
		algo = strtol(argv[1],NULL,10);
		if( (strcmp(argv[2], "setup")==0) || (strcmp(argv[2], "keygen")==0) ){
			publicfile = fopen( str_publicfile, "w");
			secretfile = fopen( str_secretfile, "w");
			if( secretfile == NULL || publicfile == NULL ){
				lerror("Unable to write to %s/%s\n",str_secretfile,str_publicfile);
				return 1;
			}

			start = clock();
			rc = a25519_keygen(algo, &pbuf, &plen, &sbuf, &slen);
			end = clock();
			cpu_time_use0 = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
			if(rc != 0){ lerror("Setup Error\n"); }
			printf("setup took %.4f ms\n", cpu_time_use0);

			write_b64( publicfile, pbuf, plen );
			write_b64( secretfile, sbuf, slen );

			fclose(publicfile);
			fclose(secretfile);

			free(pbuf);
			free(sbuf);

		}else if( (strcmp(argv[2],"ext") == 0) || strcmp(argv[2],"sign")==0 ){
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
			rc = a25519_sig_sign(algo, sbuf, slen, mbuf, mlen, &obuf, &olen);
			end = clock();
			cpu_time_use0 = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
			if(rc != 0){ lerror("Extract Error\n"); }
			printf("extract took %.4f ms\n", cpu_time_use0);

			write_b64( uskfile, obuf, olen );
			fclose(secretfile);
			fclose(idfile);
			fclose(uskfile);

			free(sbuf);
			free(mbuf);
			free(obuf);
		}else if(strcmp( argv[2],"check") == 0){

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

			rc = a25519_sig_verify( algo, pbuf, plen, mbuf, mlen, obuf, olen);

			if(rc==0){
				printf("signature valid\n");
			}else{
				printf("signature invalid\n");
			}

			fclose(publicfile);
			fclose(idfile);
			fclose(uskfile);

			free(pbuf);
			free(obuf);
			free(mbuf);

		}else if( strcmp(argv[2],"test") == 0){
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

			rc = a25519_test_offline(algo, pbuf, plen, mbuf, mlen, obuf, olen);
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

		}else if( strcmp(argv[2],"prove") == 0){
			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			if( idfile == NULL || uskfile == NULL ){
				lerror("Missing %s/%s\n",str_idfile,str_uskfile);
				return 1;
			}
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );

			if( argc > 3 ){
				rc = a25519_ibi_oclient(algo, mbuf, mlen, obuf, olen, argv[3], PORT, 60);
			}else{
				rc = a25519_ibi_oclient(algo, mbuf, mlen, obuf, olen, "127.0.0.1", PORT, 60);
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

		}else if( strcmp(argv[2],"verify") == 0){
			//ONE shot verify
			publicfile = fopen( str_publicfile, "r");
			if( publicfile == NULL ){
				lerror("Missing %s\n",str_publicfile);
				return 1;
			}
			pbuf = read_b64( publicfile, &plen );

			rc = a25519_ibi_oserver(algo, pbuf, plen, &mbuf, &mlen, PORT, 60);
			if(rc==0){
				printf("verify success [%s] 0x%02x\n", mbuf, rc);
			}else{
				printf("verify fail [%s] 0x%02x\n", mbuf, rc);
			}

			fclose(publicfile);
			free(pbuf);
			free(mbuf);

		}else if( strcmp(argv[2],"client") == 0){

			idfile = fopen( str_idfile, "r");
			uskfile = fopen( str_uskfile, "r");
			if( idfile == NULL || uskfile == NULL ){
				lerror("Missing %s/%s\n",str_idfile,str_uskfile);
				return 1;
			}
			obuf = read_b64( uskfile, &olen );
			mbuf = (unsigned char *) fileread( idfile, &mlen );
			int csock;

			if( argc > 3 ){
				csock = a25519_ibi_client(algo, mbuf, mlen, obuf, olen, argv[3], PORT, 60);
			}else{
				csock = a25519_ibi_client(algo, mbuf, mlen, obuf, olen, "127.0.0.1", PORT, 60);
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

		}else if( strcmp(argv[2],"server") == 0 ){
			//persistent verify
			publicfile = fopen( str_publicfile, "r");
			if( publicfile == NULL ){
				lerror("Missing %s\n",str_publicfile);
				return 1;
			}
			pbuf = read_b64( publicfile, &plen );

			a25519_ibi_server(algo, pbuf, plen, PORT, 10, 5,sample_callback);
			//don't expect to leave this place

		}else if( strcmp(argv[2],"runtest") == 0 ){
			if(argc > 3){
				publicfile = fopen( str_publicfile, "r");
				idfile = fopen( str_idfile, "r");
				uskfile = fopen( str_uskfile, "r");
				obuf = read_b64( uskfile, &olen );
				pbuf = read_b64( publicfile, &plen );
				mbuf = (unsigned char *) fileread( idfile, &mlen );
				unsigned int count = int_testcnt;

				if( strcmp(argv[3],"prove") == 0 ){
					if(argc > 4){
						a25519_test_client(algo, mbuf, mlen, obuf, olen, argv[4], PORT, count );
					}else{
						a25519_test_client(algo, mbuf, mlen, obuf, olen, "127.0.0.1", PORT, count );
					}
				}else if( strcmp(argv[3],"verify") == 0){
					//verifies for 100 times
					a25519_test_server(algo, pbuf, plen, PORT, count );
				}else if( strcmp(argv[3],"signat") == 0){
					unsigned char mbuf[] = str_teststr;

					start = clock();
					for( i = 0 ; i < int_testcnt ; i++){
						a25519_keygen(algo, &pbuf, &plen, &sbuf, &slen);
					}
					end = clock();
					//millis averaged
					cpu_time_use0 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;

					start = clock();
					for( i = 0 ; i < int_testcnt ; i++){
						a25519_sig_sign(algo,sbuf, slen, mbuf, strlen(mbuf), &obuf, &olen);
					}
					end = clock();
					//millis averaged
					cpu_time_use1 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;

					start = clock();
					for( i = 0 ; i < int_testcnt ; i++){
						rc = a25519_sig_verify(algo, pbuf, plen, mbuf, strlen(mbuf), obuf, olen);
					}
					end = clock();
					//millis averaged
					cpu_time_use2 = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000) / int_testcnt;
					printf("Final res: %d\n", rc);
					printf("keygen %d/: %f ms\n", int_testcnt, cpu_time_use0 );
					printf("sign /%d: %f ms\n", int_testcnt, cpu_time_use1 );
					printf("verify /%d: %f ms\n", int_testcnt, cpu_time_use2 );

					free(sbuf); free(pbuf); free(obuf);
				}else if( strcmp(argv[3],"of") == 0){
					//correctness and memory test
					unsigned char mbuf[1024];
					int fd = open("/dev/urandom", O_RDONLY);

					cpu_time_use0 = 0;
					for( i=0; i< int_testcnt; i++){
						read(fd, mbuf, 1024);
						a25519_keygen(algo, &pbuf, &plen, &sbuf, &slen);
						a25519_sig_sign(algo, sbuf, slen, mbuf, 1024, &obuf, &olen);

						// signature test
						//rc = a25519_sig_verify(algo, pbuf, plen, mbuf, 1024, obuf, olen);
						//if(rc != 0){
						//	printf("Invalid signature on iter. %u\n",i);
						//	break;
						//}

						start = clock();
						rc = a25519_test_offline(algo, pbuf, plen, mbuf, 1024, obuf, olen);
						end = clock();
						cpu_time_use0 += ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000);
						if(rc != 0){
							printf("Invalid offline proto on iter. %u\n",i);
							break;
						}
					}
					cpu_time_use2 = cpu_time_use0 / int_testcnt;
					printf("offline full test done iter. %u @ %f \n",i,cpu_time_use2);
				}
			}else{
				lerror("Please specify either <prove|verify|signat|of> for runtest !\n");
				return 1;
			}
		}else{
			//echo an error
			lerror("Invalid mode %s, please specify either:\n	<keygen/setup|sign/ext|check|prove|verify|server|client|test|runtest> !\n", argv[2]);
			return 1;
		}

		printf("a25519 run OK.\n");
		return 0;
	}else{
		//echo an error
		lerror("Insufficient args, please specify either:\n<mode>\t<keygen/setup|sign/ext|check|prove|verify|server|client|test|runtest> !\n\nmodes:\n0 - tnc25519\n1 - cli25519\n2 - sch25519\n");
		return 1;
	}

}
