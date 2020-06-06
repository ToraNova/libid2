/*
 * Generic protocols (ID negotiation, send OK or NACK)
 *
 * id2 project
 * chia_jason96@live.com
 */

#ifndef _GEN_PROTO_HPP_
#define _GEN_PROTO_HPP_

//go-ahead
#define SIG_GA 0x5a

#include <stddef.h>

namespace general{

	namespace client{
		//establish a protocol by sending ID over as client
		//return 0 on succeed, abort protocol otherwise
		int establish(int sock, unsigned char *mbuffer, size_t mlen);

	}

	namespace server{
		//establish a protocol by receiving ID over as server
		//return 0 on succeed, abort protocol otherwise
		int establish(int sock, unsigned char **mbuffer, size_t *mlen);
	}

}

#endif
