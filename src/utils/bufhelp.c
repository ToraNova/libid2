/*
  Buffer utility function
  prints out buffers

  ToraNova 2020
  chia_jason96@live.com
*/

#include "bufhelp.h"
#include <stdio.h>
#include <string.h>

void ucbprint(const unsigned char *buf, size_t sz){
	size_t c;
	for(c=0;c<sz;c++){
		printf("%02X",buf[c]);
	}
}

size_t copyskip(unsigned char *dst, const unsigned char *src, size_t skip, size_t size){
	memcpy( dst+skip, src, size);
	return skip+size;
}

size_t skipcopy(unsigned char *dst, const unsigned char *src, size_t skip, size_t size){
	memcpy( dst, src+skip, size);
	return skip+size;
}
