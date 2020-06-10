/*
 * <TEMPLATE> signature scheme key conversion functions
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include "static.hpp"
#include "proto.hpp"

// include general prototype and macro
#include "../proto.hpp"
#include "../cmacro.h"

//mini socket library
#include "../../utils/bufhelp.h"
#include "../../utils/debug.h"
#include "../../utils/simplesock.h"

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <cstring>

namespace <TEMPLATE>{

namespace client{

int executeproto(
	int sock,
	unsigned char *mbuffer, size_t mlen,
	struct signat *usk
){
	if(sock == -1){return -1;}; int rc;
	unsigned char buf[TS_MAXSZ] = {0};
}

}

namespace server{

int executeproto(
	int sock,
	unsigned char *mbuffer, size_t mlen,
	struct pubkey *par
){
	if(sock == -1){return 1;}; int rc;
	unsigned char buf[TS_MAXSZ] = {0};

	return rc;
}

}

//general (non client or server namespace)
int putest(
	struct pubkey *par,
	struct signat *usk,
	unsigned char *mbuffer, size_t mlen
){
	int rc;

	return rc;
}

}
