/*
 * a25519.cpp - id2 library
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Chia Jason
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * File: a25519.cpp (algorithm for curve25519 based IBI and signatures)
 * Signature and identity-based identification algorithms
 * based of Finite-field arithmetic over Curve25519 (libsodium)
 * https://nacl.cr.yp.to/install.html
 * Toranova 2019
 * chia_jason96@live.com
*/

// declaration includes
#include "a25519.hpp"
#include "utils/debug.h"
#include "utils/bufhelp.h"
#include "utils/simplesock.h"

//internals
#include "internals/proto.hpp"
#include "internals/ifcall.hpp"

// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

namespace a25519
{
	//standard signatures
	int keygen(
		unsigned int a,
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//create a key
		void *key;
		//generate random key
		//tnc25519::randomkey(&key);
		iftable[a]->randkeygen(&key);
		if(key == NULL)return 1;

		//serialize the key to string
		iftable[a]->secserial(key, sbuffer, slen);
		iftable[a]->pubserial(key, pbuffer, plen);

#ifdef DEBUG
iftable[a]->secprint(key);
printf("sbuffer %lu: ",*slen); ucbprint(*sbuffer, *slen); printf("\n");
printf("pbuffer %lu: ",*plen); ucbprint(*pbuffer, *plen); printf("\n");
#endif

		//clear the key
		iftable[a]->secdestroy(key);

		return 0;
	}

namespace sig{

	int sign(
		unsigned int a,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		void *key;
		void *sig;
		//obtain key from serialize string
		iftable[a]->secstruct(sbuffer, slen, &key);
		//signature generation
		iftable[a]->signatgen(key, mbuffer, mlen, &sig);

		debug("test\n");
		//clear the secret key
		iftable[a]->secdestroy(key);

		//serialize the signature to string
		iftable[a]->sigserial(sig, obuffer, olen);


#ifdef DEBUG
iftable[a]->sigprint(sig);
printf("obuffer %lu: ",*olen); ucbprint(*obuffer, *olen); printf("\n");
#endif

		//clear the signature
		iftable[a]->sigdestroy(sig);

		return 0;
	}

	int verify(
		unsigned int a,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		//obtain paramter (public key) and signature from serialize string
		void *par;
		void *sig;
		iftable[a]->pubstruct(pbuffer, plen, &par);
		iftable[a]->sigstruct(obuffer, olen, &sig);

		rc = iftable[a]->signatchk(par, sig, mbuffer, mlen);

		iftable[a]->sigdestroy(sig);
		iftable[a]->pubdestroy(par);
		return rc;
	}
}

namespace ibi{

	int prove(
		unsigned int a,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int csock
	){
		if(csock == -1){
			lerror("Invalid socket\n");
			return 1;
		}

		int rc;
		//parse the usk
		void *usk;
		iftable[a]->sigstruct(obuffer, olen, &usk);

		debug("Sending ID string %s\n",mbuffer);
		rc = general::client::establish( csock, mbuffer, mlen );
		if(rc != 0){
			lerror("Failed to recv go-ahead (0x5a) byte\n");
			return 1;
		}
		debug("Go-Ahead received (0x5a), Starting PROVE protocol\n");

		rc = iftable[a]->signatprv( csock, usk, mbuffer, mlen);

		//free up the usk
		iftable[a]->sigdestroy(usk);
		return rc;
	}

	int verify(
		unsigned int a,
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int csock
	){
		if(csock == -1){
			lerror("Invalid socket\n");
			return 1;
		}

		int rc;
		//parse the params (public key)
		void *par;
		iftable[a]->pubstruct(pbuffer, plen, &par);

		rc = general::server::establish( csock, mbuffer, mlen );
		if(rc != 0){
			lerror("Failed to recv ID from prover\n");
			return 1;
		}
		debug("Go-Ahead sent (0x5a), Starting VERIFY protocol\n");
		rc = iftable[a]->signatvrf( csock, par, *mbuffer, *mlen);

		//free up
		iftable[a]->pubdestroy(par);
		return rc;
	}

	int oclient(
		unsigned int a,
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

		rc = prove(a, mbuffer, mlen, obuffer, olen, tsock );
		close(tsock);
		return rc;
	}

	// PLEASE CLOSE THE SOCKET YOURSELF AFTER USING.
	int client(
		unsigned int a,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port, int timeout
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

		rc = prove(a, mbuffer, mlen, obuffer, olen, tsock );
		if(rc==0){
			return tsock;
		}else{
			return -1;
		}
	}

	//one shot server
	int oserver(
		unsigned int a,
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
		rc = verify(a, pbuffer, plen, mbuffer, mlen, csock );
		close(csock);
		close(ssock);
		return rc;
	}


	//TODO: implement this with 'select'
	void server(
		unsigned int a,
		unsigned char *pbuffer, size_t plen,
		int port, int timeout, int maxcq,
		void (*callback)(int, int, const unsigned char *, size_t)
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
			rc = verify(a, pbuffer, plen, &mbuffer, &mlen, csock );
			callback(rc, csock, mbuffer, mlen ); //runs the callback func
			close(csock);
		}
	}


}

namespace test{

	int offline(
		unsigned int a,
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		void *par;
		void *usk;
		iftable[a]->pubstruct(pbuffer, plen, &par);
		iftable[a]->sigstruct(obuffer, olen, &usk);

		//run test
		rc = iftable[a]->prototest(par, usk, mbuffer, mlen);

		//clear out
		iftable[a]->pubdestroy(par);
		iftable[a]->sigdestroy(usk);

		return rc;
	}


	void client(
		unsigned int a,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		const char *srv, int port,
		unsigned int count
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
			rc = ibi::prove(a, mbuffer, mlen, obuffer, olen, tsock );
			if(rc!=0){
				lerror("Invalid run:%u, rc=%d\n",i,rc);
				break;
			}
		}
		end = clock();
		cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
		printf("%d proves took total %.4f ms, ", count, cpu_time_use);
		cpu_time_use = cpu_time_use / count; //average it
		printf("average: %.4f ms\n", cpu_time_use);
		if(i==count) printf("All runs OK\n");
		close(tsock);
	}

	//similar to server,
	//but records average time and expect 100 authentication attempts
	//FOR testing purposes
	void server(
		unsigned int a,
		unsigned char *pbuffer, size_t plen,
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
			rc = ibi::verify(a, pbuffer, plen, &mbuffer, &mlen, csock );
			if(rc!=0){
				lerror("Invalid run:%u, rc=%d\n",i,rc);
				break;
			}
			//callback(rc, csock, mbuffer, mlen ); //runs the callback func
		}
		end = clock();

		//calculation
		cpu_time_use = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000; //record time
		printf("%d verifications took total %.4f ms, ", count, cpu_time_use);
		cpu_time_use = cpu_time_use / count; //average it
		printf("average: %.4f ms\n", cpu_time_use);
		if(i==count) printf("All runs OK\n");

		close(csock);
	}

}

}
