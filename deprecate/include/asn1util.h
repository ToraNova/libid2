/*
  File utility functions for the id2 project
  This is for ASN1 output encoding/decoding
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _ASN1UTIL_H_
#define _ASN1UTIL_H_

#include <stddef.h>
#include <stdio.h>

#define TYPE_PUBLIC 0
#define TYPE_SECRET 1

#ifdef __cplusplus
extern "C"{
#endif

// ed25519 output keys
void e25519_asn1_der_out(FILE *stream, const unsigned char *key, size_t klen, unsigned int type);
// ed25519 input keys (please clear the returned array after use with free() )
unsigned char *e25519_asn1_der_in(FILE *stream, size_t *klen, unsigned int type);

#ifdef __cplusplus
};
#endif

#endif
