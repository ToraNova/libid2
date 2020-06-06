/*
 * TNCIBI protocol scheme
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is (mainly) for internal use only!
 */

#ifndef _TNC_PROTO_HPP_
#define _TNC_PROTO_HPP_

#include <stddef.h>
#include "static.hpp"

namespace tnc {

	namespace client{

		// execute ibi protocol as client
		// sock - the socket connection to server
		// mbuffer, mlen - id of user/prover
		// usk - usk struct (signature) of prover
		int executeproto(
			int sock,
			unsigned char *mbuffer, size_t mlen,
			struct signat *usk
		);

	}

	namespace server{

		// execute ibi protocol as server
		// sock - the socket connection to client
		// par - the parameter of ibi system (public key of kgc)
		// mbuffer - the client identifying on other end (OUTPUT)
		int executeproto(
			int sock,
			struct pubkey *par,
			unsigned char **mbuffer, size_t *mlen
		);

	}
}

#endif
