/*
 * internals/proto.hpp - id2 library
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

#ifndef _GEN_PROTO_HPP_
#define _GEN_PROTO_HPP_

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
