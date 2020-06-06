/*
 * Generic protocols (ID negotiation, send OK or NACK)
 *
 * id2 project
 * chia_jason96@live.com
 */

#include "proto.hpp"

//mini socket library
#include "../utils/debug.h"
#include "../utils/simplesock.h"

#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace general{
namespace client{
	//establish a protocol by sending ID over as client
	int establish(int sock, unsigned char *mbuffer, size_t mlen){
		if(sock == -1){return -1;}
		unsigned char buf[1];
		//TODO: implement a check here on the number of bytes sent
		sendbuf(sock, (char *)mbuffer , mlen);
		//await byte 0x5a before proceeding with protocol
		if( fixed_recvbuf(sock, (char *)buf, 1) < 0 || buf[0] != SIG_GA){
			return 2;
		}
		return 0;
	}
}

namespace server{
	//establish a protocol by receiving ID over as server
	int establish(int sock, unsigned char **mbuffer, size_t *mlen){
		if(sock == -1){return -1;}
		int rc;
		unsigned char buf[CONN_MAXBF_SIZE] = {0};
		unsigned char ackp[1] = { SIG_GA };
		//receive ID
		rc = recvbuf(sock, (char *)buf, CONN_MAXBF_SIZE);
		//if received nothing or zero len string, exit
		if( rc <= 0 ){return 1;}
		*mlen = (size_t)rc;
		*mbuffer = (unsigned char *)malloc(*mlen);
		memcpy( *mbuffer, buf, *mlen );
		//send a go-ahead
		if( send(sock, ackp, 1, 0) < 0){
			return 2;
		}
		return 0;
	}
}
}
