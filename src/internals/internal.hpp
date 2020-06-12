/*
 * internals/internal.hpp - id2 library
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

#ifndef _INTERNAL_HPP_
#define _INTERNAL_HPP_
struct algostr{
	void (*randkeygen)(void **);
	//void (*signatgen)( void *, unsigned char *, size_t );
	//void (*signatchk)( void *, void *, unsigned char *, size_t );

	//void (*secserial)( void *, unsigned char **, size_t *);
	//void (*pubserial)( void *, unsigned char **, size_t *);
	//void (*sigserial)( void *, unsigned char **, size_t *);
	//void (*secstruct)( unsigned char *, size_t);
	//void (*pubstruct)( unsigned char *, size_t);
	//void (*sigstruct)( unsigned char *, size_t);

	//void (*secdestroy)(void *);
	//void (*pubdestroy)(void *);
	//void (*sigdestroy)(void *);

	//void (*secprint)(void *);
	//void (*pubprint)(void *);
	//void (*sigprint)(void *);

	//void (*client)(int, unsigned char *, size_t, void *);
	//void (*server)(int, unsigned char *, size_t, void *);
	//void (*putest)(void *, void *, unsigned char *, size_t);
};
#endif
