/*
  Buffer utility function
  prints out buffers

  ToraNova 2020
  chia_jason96@live.com
*/

#include <stddef.h>

#ifndef _BUFHELPER_H_
#define _BUFHELPER_H_

#ifdef __cplusplus
extern "C"{
#endif

	void ucbprint(const unsigned char *buf, size_t sz);
	//copy src to dest+skip with size, return the next 'skip' value
	size_t copyskip(unsigned char *dest, const unsigned char *src, size_t skip, size_t size);
	//copy src+skip to dest with size, return the next 'skip' value
	size_t skipcopy(unsigned char *dest, const unsigned char *src, size_t skip, size_t size);

#ifdef __cplusplus
};
#endif

#endif
