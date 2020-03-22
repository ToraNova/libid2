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

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/randombytes.h>
//512bit hash (64byte)
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_verify_32.h>

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

	/*
	 * Don't touch the following until security is proven
	 */
	int oclient(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout
	){
		int tsock;
		int rc;

		//Create socket
		tsock = sockgen(timeout, 1, 0);
		if(tsock == -1){lerror("Socket creation failed\n");return 1;}

		//Attempt to connect
		debug("Attempting to connect to %s:%d\n",srv,port);
		if( sockconn(tsock, srv, port) < 0){
			lerror("Failed to connect to verifier\n");
			return 1;
		}
		debug("Connection established with %s:%d\n",srv,port);

		rc = prove( mbuffer, mlen, obuffer, olen, tsock );
		close(tsock);

		return rc;
	}

	// PLEASE CLOSE THE SOCKET YOURSELF AFTER USING.
	int client(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int timeout
	){
		int tsock, rc;
		//Create socket
		tsock = sockgen(timeout, 1, 0);
		if(tsock == -1){lerror("Socket creation failed\n");return 1;}

		//Attempt to connect
		debug("Attempting to connect to %s:%d\n",srv,port);
		if( sockconn(tsock, srv, port) < 0){
			lerror("Failed to connect to verifier\n");
			return 1;
		}
		debug("Connection established with %s:%d\n",srv,port);

		rc = prove( mbuffer, mlen, obuffer, olen, tsock );
		if(rc==0){
			return tsock;
		}else{
			return -1;
		}
	}

	void tclient(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		int count
	){
		int tsock;
		int rc;
		clock_t start, end; unsigned int i;
		double cpu_time_use = 0;

		//Create socket
		tsock = sockgen(60, 1, 0);
		if(tsock == -1){lerror("Socket creation failed\n");return;}

		//Attempt to connect
		debug("Attempting to connect to %s:%d\n",srv,port);
		if( sockconn(tsock, srv, port) < 0){
			lerror("Failed to connect to verifier\n");
			return;
		}
		debug("Connection established with %s:%d, begin prove tests\n",srv,port);

		start = clock();
		for(i=0; i<count;i++){
			rc = prove( mbuffer, mlen, obuffer, olen, tsock );
		}
		end = clock();
		cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
		printf("%d proves took total %.4f ms, ", count, cpu_time_use);
		cpu_time_use = cpu_time_use / count; //average it
		printf("average: %.4f ms\n", cpu_time_use);
		close(tsock);
	}
}
