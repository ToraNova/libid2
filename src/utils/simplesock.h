/*
 * Simplesock.h
 * Simple socket library
 * ToraNova 2019
 */

#ifndef _SIMPLESOCK_H_
#define _SIMPLESOCK_H_

//instructs g++ to not perform name mangling here
//the nested declares are c functions
#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>
#include <unistd.h>

#define SEND_BATCH_SIZE 1024

//creates a socket connection timeout_sec to set send and receive timeout for that socket
//set timeout_sec to 0 for notimeout. reuse - allow quick rebinding of socket
//nonblock - won't wait
int sockgen(int timeout_sec, short reuse, short nonblock); //create the socket connection

//connect to a srv:port for the sock obj
int sockconn(int sock,const char *srv,int port); //connect to a socket

//bind to a port (server)
int sockbind(int sock,int port); //bind the socket connection

//send a buffer
int sendbuf(int sock, char *sendbuf, size_t buflen); //send via the socket connection

//receive a buffer
int recvbuf(int sock, char *recvbuf, size_t buflen); //recv via the socket connection

//receive a fixed length, or return error otherwise
int fixed_recvbuf(int sock, char *recvbuf, size_t buflen); //fixed length recv via the socket connection

#ifdef __cplusplus
};
#endif

#endif
