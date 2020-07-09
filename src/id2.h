/*
 * Main include file - id2 library
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

#ifndef _ID2_H_
#define _ID2_H_

#include "a25519.h"

//TODO please keep this updated
#define A25519_TNC 		0
#define A25519_CLI 		1	//TODO: not implemented
#define A25519_SCHNORR 		2	//TODO: not implemented
#define A25519_TWINSCHNORR	3	//TODO: not implemented
#define A25519_TIGHTSCHNORR	4	//TODO: not implemented
#define A25519_RESETSCHNORR	5	//TODO: not implemented
#define A25519_RESET2SCHNORR	6	//TODO: not implemented

//TODO c bindings for internals
// Or do we really need it?

//auxiliary helpers
#include "utils/debug.h"
#include "utils/jbase64.h"
#include "utils/futil.h"
#include "utils/asn1util.h"

#ifdef __cplusplus
extern "C"{
#endif

//initialize the library
//basically just calls sodium_init()
int id2_initialize();

#ifdef __cplusplus
}
#endif

#endif
