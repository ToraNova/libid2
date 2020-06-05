/*
  Buffer utility function
  prints out buffers

  ToraNova 2020
  chia_jason96@live.com
*/

#include "bufhelp.h"
#include <stdio.h>

void ucbprint(unsigned char *buf, size_t sz){
	size_t c;
	for(c=0;c<sz;c++){
		printf("%02X",buf[c]);
	}
}
