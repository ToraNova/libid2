/*
 * internals/cmacro.h - id2 library
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
 * Constants and macro file
 * stores all defines here
 *
 * PLEASE DO NOT STORE CONFIGURATION MACROS, use autotools for that instead!
 *
 * ToraNova 2020
 * chia_jason96@live.com
 */

#ifndef _CMACRO_H_
#define _CMACRO_H_

// SIZES
// Ristretto255
#define RS_EPSZ crypto_core_ristretto255_BYTES
#define RS_SCSZ crypto_core_ristretto255_SCALARBYTES
#define RS_HSSZ crypto_core_ristretto255_HASHBYTES

// TCP socket
#define TS_MAXSZ 1024

// SIGNALS
//go-ahead
#define SIG_GA 0x5a



#endif

