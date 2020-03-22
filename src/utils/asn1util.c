/*
  File utility functions for the id2 project
  This is for ASN1 output encoding/decoding
  ToraNova 2019
  chia_jason96@live.com
*/

// file utils
#include "asn1util.h"
#include "debug.h"
#include "jbase64.h"
#include "futil.h"

// standard lib
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ed25519 output keys, prepending a string of bytes following asn1 format
void e25519_asn1_der_out(FILE *stream,
		const unsigned char *key, size_t klen,
		unsigned int type){
	size_t i,s,p; char *enc;

	const unsigned char pubpre[12] = {
		0x30,0x2A,			// 0x2A = 12+32 = 43
		0x30,0x05,
		0x06,0x03,0x2B,0x65,0x70, 	// curve25519 EdDSA
		0x03,0x21,0x00
	};

	const unsigned char secpre[16] = {
		0x30,0x2E,			// 0x2E = 16+32 = 48
		0x02,0x01,0x00,
		0x30,0x05,
		0x06,0x03,0x2B,0x65,0x70, 	// curve25519 EdDSA
		0x04,0x22,0x04,0x20
	};

	if(type == TYPE_PUBLIC ) {
		p = 12;
		s = p+klen;
	} else {
		p = 16;
		s = p+klen-32; //remove the public key from the private key
	}
	debug("klen: %lu: WSZ: %lu, PRSZ: %lu\n",klen,s,p);

	unsigned char *out = (unsigned char *)malloc( s );

	if(type == TYPE_PUBLIC ){
		for(i=0;i<p;i++) out[i] = pubpre[i];
		for(i=0;i<klen;i++) out[i+p] = key[i];
	} else {
		for(i=0;i<p;i++) out[i] = secpre[i];
		for(i=0;i<klen-32;i++) out[i+p] = key[i];
	}
	enc = b64_encode( out, s, BASE64_DEFAULT_WRAP);

	if(type == TYPE_PUBLIC) fprintf(stream, "-----BEGIN PUBLIC KEY-----\n");
	else fprintf(stream, "-----BEGIN PRIVATE KEY-----\n");

	fprintf(stream, "%s\n", enc );

	if(type == TYPE_PUBLIC) fprintf(stream, "-----END PUBLIC KEY-----\n");
	else fprintf(stream, "-----END PRIVATE KEY-----\n");

	free(out);
}

// ed25519 input keys (please clear the returned array after use with free() )
// return NULL on fail
unsigned char *e25519_asn1_der_in(FILE *stream, size_t *klen, unsigned int type){

	unsigned char *out, *dec; char *read;
	size_t rlen, i, j, t;
	read = fileread(stream, &rlen);
	//find the newline character
	if( read == NULL) return NULL;
	for(i=0;i<rlen;i++){
		if( read[i] == '\n' ) break;
	}
	i++; //start reading AFTER the newline
	//find the '-' char, trim there
	for(j=i; j<rlen;j++){
		if( read[j] == '-' ) break;
	}
	read[j] = '\0'; //set up our own null terminator
	debug("NLP: %lu, DSP: %lu\n",i,j);
	dec = b64_decode(read + i);

	//skip over the preamble
	if( type == TYPE_PUBLIC ){
		t = 12;
	}else{
		t = 16;
	}

	*klen = b64_decoded_size(read + i );
	*klen -= t;
	out = (unsigned char *)malloc( *klen );
	for(j=0;j< *klen;j++){
		out[j] = dec[j+t];
	}
	debug("b64d sz: %lu\n",*klen);
	return out;
}
