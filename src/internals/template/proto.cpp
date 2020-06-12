/*
 * <TEMPLATE> - id2 library
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