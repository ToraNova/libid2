/*
 * internals/proto.cpp - id2 library
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
 * Generic protocols (ID negotiation, send OK or NACK)
 *
 * id2 project
 * chia_jason96@live.com
 */

#include "proto.hpp"
#include "cmacro.h"

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
		unsigned char buf[TS_MAXSZ] = {0};
		unsigned char ackp[1] = { SIG_GA };
		//receive ID
		rc = recvbuf(sock, (char *)buf, TS_MAXSZ);
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
