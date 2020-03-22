/*
simple socket connection library for c

written for a machine learning tutorial
as of 2020 Mar 23, this is used as a quick bootstrap for C projects.
now placed in template-autoc
chia_jason96@live.com

guided strongly by (credits to the original author)
https://aticleworld.com/socket-programming-in-c-using-tcpip/
*/

#include "simplesock.h"
#include "debug.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

extern int errno;

int sockgen(int timeout_sec, short reuse, short nonblock){
	// create the socket connection
	// timeout_sec - connection timeout in seconds
	// if reuse is set to 1, binds immediately again
	// if nonblock is set to 1, socket is non blocking on recv/send
	int sockobj;

	struct timeval timeout; //setup the timeout
	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	sockobj = socket(
		AF_INET,
		nonblock? SOCK_STREAM | SOCK_NONBLOCK : SOCK_STREAM ,
		0); //set protocol to 0 perhaps STREAM only supported by TCP

	//perform timeout setup for SEND and RECEIVE
	if(setsockopt(sockobj,SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) < 0){
		lerror("Socket set options failed. %d\n",timeout_sec);
		perror("sockgen : setsockopt - snd timeout");
		return -1;
	}
	if(setsockopt(sockobj,SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0){
		lerror("Socket set options failed. %d\n",timeout_sec);
		perror("sockgen : setsockopt - rcv timeout");
		return -1;
	}
	debug("Socket set to timeout for SEND and RECV (%ds)\n",timeout_sec);

	if(setsockopt(sockobj,SOL_SOCKET, SO_REUSEADDR, &reuse,sizeof(int)) < 0){
		lerror("Socket set options failed. %d\n",reuse);
		perror("sockgen : setsockopt - reuse");
		return -1;
	}
	return sockobj;
}

int sockconn(int sockobj, const char *srvaddr,int portnum){
	//connect to a socket server
	int retval = -1;
	struct sockaddr_in remote={0};

	//setup connection params
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(srvaddr);
	remote.sin_port = htons(portnum);

	//attempt to connect, obtaining the result code as retval.
	retval = connect(sockobj, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));
	debug("Connection to %s on port %d returns %d\n",srvaddr,portnum,retval);
	return retval;
}

int sockbind(int sockobj, int portnum){
	//bind the created socket
	int retval = -1;
	struct sockaddr_in remote={0};

	//setup connection params
	remote.sin_addr.s_addr = htonl(INADDR_ANY);
	remote.sin_family = AF_INET;
	remote.sin_port = htons(portnum);

	retval = bind(sockobj,(struct sockaddr *)&remote,sizeof(struct sockaddr_in));
	debug("Socket bound to port %d returns %d\n",portnum,retval);
	return retval;
}

int sendbuf(int sockobj, char *sendbuffer, size_t buflen){
	//send via the socket connection
	uint32_t bleft = buflen;
	uint32_t thisbatch = 0;
	uint32_t ptrindex = 0;
	int sent = 0;

	//code enters here when setup is successful
	while( bleft > 0 ){
		if(buflen > SEND_BATCH_SIZE) thisbatch = SEND_BATCH_SIZE;
		else thisbatch = bleft;
		sent = send(sockobj, sendbuffer+ptrindex, thisbatch,0);
		if(sent == -1)break;
		ptrindex += sent;
		bleft -= sent;
	}
	debug("Buffer of size %zu sent with retval:%d\n",buflen,sent);
	return sent;
}

int recvbuf(int sockobj, char *recvbuffer, size_t buflen){
	//recv via the socket connection
	int retval = -1;
	retval = recv(sockobj, recvbuffer, buflen, 0);
	debug("Buffer of size %zu recv with retval:%d\n",buflen,retval);
	return retval;
}

int fixed_recvbuf(int sockobj, char *recvbuffer, size_t buflen){
	//recv via the socket connection
	//must receive buflen or else it will not stop.
	uint32_t bleft = buflen;
	uint32_t thisbatch = 0;
	uint32_t ptrindex = 0;
	int brecv = 0;

	while( bleft > 0 ){
		if(buflen > SEND_BATCH_SIZE) thisbatch = SEND_BATCH_SIZE;
		else thisbatch = bleft;
		brecv = recv(sockobj, recvbuffer+ptrindex, thisbatch,0); //here it will block
		if(brecv <= 0)break;
		ptrindex += brecv;
		bleft -= brecv;
	}
	debug("Buffer of size %zu recv with retval:%d/%lu\n",buflen,ptrindex,buflen);
	return brecv == -1 ? brecv : ptrindex ;
}
