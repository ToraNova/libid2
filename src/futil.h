/*
  File utility functions for the paircrypt project
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _FUTIL_H_
#define _FUTIL_H_

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"{
#endif

// write a char array to file as base64 (pure base64)
void write_b64(FILE *stream, const unsigned char *target, size_t length);

//read the file which is base64 encoded
//return NULL on fail, also please clear the returned array after use
unsigned char *read_b64(FILE *stream, size_t *length);

// read a file and outputs a char array as is from a file
//return NULL on fail, also please clear the returned array after use
char *fileread(FILE *stream, size_t *length);

//convert hex string to unsigned char array
unsigned char *hexstr2uc(const char *s, size_t *length);

#ifdef __cplusplus
};
#endif

#endif
