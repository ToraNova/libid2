/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 * abbreviated as ti25519 - TNC identification using 25519
 *
*/

// declaration includes
#include "tsi25519.hpp"
#include "utils/debug.h"

//mini socket library
#include "utils/simplesock.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>


// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * msk - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * mpk - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 * usk  - < 256 s >< 256 x >< 256 U >< 256 V >< 256 B > (does not need to store mpk anymore)
 *
 */
namespace ti25519{

	//one shot server
	int oserver(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int port, int timeout
	){
		struct sockaddr_in cli; int rc;
		struct in_addr ipaddr;
		char ipastr[INET_ADDRSTRLEN];
		int ssock,csock; //server socket and client socket
		int cli_len = sizeof(struct sockaddr_in);

		//Create socket (timeout, rebind, nonblock)
		ssock = sockgen(timeout, 1, 0);
		if(ssock == -1){lerror("Socket creation failed\n");return 1;}
		//bind the socket
		if(sockbind(ssock,port) < 0){lerror("Port bind failed\n");return 1;}

		//listen for incoming conn
		debug("Listening for verification attempts on port %d\n",port);
		listen(ssock, 0);

		csock = accept( ssock, (struct sockaddr *)&cli, (socklen_t*)&cli_len);
		ipaddr = cli.sin_addr;
		inet_ntop( AF_INET, &ipaddr, ipastr, INET_ADDRSTRLEN );
		if(csock < 0){lerror("Connection failed to establish with %s\n",ipastr);return 1;}
		debug("Connection established with %s\n",ipastr);
		rc = verify( pbuffer, plen, mbuffer, mlen, csock );
		close(csock);
		close(ssock);
		return rc;
	}


	//TODO: implement this with 'select'
	void server(
		unsigned char *pbuffer, size_t plen,
		void (*callback)(int, int, const unsigned char *, size_t),
		int port, int timeout, int maxcq
	){
		struct sockaddr_in cli; int rc;
		int cli_len = sizeof(struct sockaddr_in);
		struct in_addr ipaddr;
		char ipastr[INET_ADDRSTRLEN];
		int ssock,csock; //server socket and client socket
		unsigned char *mbuffer; size_t mlen;

		//Create socket (timeout, rebind, nonblock)
		//Force a minimum timeout (since misprogrammed client could jam the server)
		if(timeout <= 30 || timeout > 300) timeout = 30;
		//ensure maxcq >= 0
		if(maxcq < 0) maxcq = 0;
		ssock = sockgen(timeout, 1, 0);
		if(ssock == -1){lerror("Socket creation failed\n");return;}
		//bind the socket
		if(sockbind(ssock,port) < 0){lerror("Port bind failed\n");return;}

		//listen for incoming conn
		debug("Listening for verification attempts on port %d\n",port);
		listen(ssock, maxcq);

		while(1){
			csock = accept( ssock, (struct sockaddr *)&cli, (socklen_t*)&cli_len);
			if(csock < 0){
				//lerror("Connection failed to establish with %s\n",ipastr);
				continue;
			}
			ipaddr = cli.sin_addr;
			inet_ntop( AF_INET, &ipaddr, ipastr, INET_ADDRSTRLEN );
			debug("Connection established with %s\n",ipastr);
			rc = verify( pbuffer, plen, &mbuffer, &mlen, csock );
			callback(rc, csock, mbuffer, mlen ); //runs the callback func
			close(csock);
		}
	}

	//sample implementation of a callback function
	void sample_callback(int rc, int csock, const unsigned char *mbuffer, size_t mlen){
		if(rc==0){
			printf("verify success [%s] 0x%02x\n", mbuffer, rc);
		}else{
			printf("verify fail [%s] 0x%02x\n", mbuffer, rc);
		}
		return;
	}

	//similar to server, but records average time and expect 100 authentication attempts
	//FOR testing purposes
	void tserver(
		unsigned char *pbuffer, size_t plen,
		//void (*callback)(int, int, const unsigned char *, size_t),
		int port, unsigned int count
	){
		struct sockaddr_in cli; int rc;
		int cli_len = sizeof(struct sockaddr_in);
		struct in_addr ipaddr;
		char ipastr[INET_ADDRSTRLEN];
		int ssock,csock; //server socket and client socket
		clock_t start, end; unsigned int i;
		double cpu_time_use = 0;
		unsigned char *mbuffer; size_t mlen;

		ssock = sockgen(60, 1, 0);
		if(ssock == -1){lerror("Socket creation failed\n");return;}
		//bind the socket
		if(sockbind(ssock,port) < 0){lerror("Port bind failed\n");return;}

		//listen for incoming conn
		debug("Testing for verification attempts on port %d\n",port);
		listen(ssock, 0);

		csock = accept( ssock, (struct sockaddr *)&cli, (socklen_t*)&cli_len);
		ipaddr = cli.sin_addr;
		inet_ntop( AF_INET, &ipaddr, ipastr, INET_ADDRSTRLEN );
		if(csock < 0){lerror("Connection failed to establish with %s\n",ipastr);}
		debug("Connection established with %s, begin verification tests\n",ipastr);

		//record
		start = clock();
		for(i = 0; i < count; i++){
			rc = verify( pbuffer, plen, &mbuffer, &mlen, csock );
			//callback(rc, csock, mbuffer, mlen ); //runs the callback func
		}
		end = clock();

		//calculation
		cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
		printf("%d verifications took total %.4f ms, ", count, cpu_time_use);
		cpu_time_use = cpu_time_use / count; //average it
		printf("average: %.4f ms\n", cpu_time_use);

		close(csock);
	}


}
