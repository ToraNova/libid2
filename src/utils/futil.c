/*
 * File utils for the paircrypt project
 * ToraNova2019
*/

// file utils
#include "futil.h"
#include "debug.h"
#include "jbase64.h"

// standard lib
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

//read the file which is base64 encoded
//return NULL on fail
unsigned char *read_b64(FILE *stream, size_t *length){
	unsigned char *out; char *read;
	size_t rlen;
	read = fileread(stream, &rlen);

	out = b64_decode(read);
	//*length = strlen((const char *)out); //dont
	*length = b64_decoded_size(read);
	debug("b64d sz: %lu from %lu b64 chars\n",*length,rlen);
	free(read);
	return out;
}


//writes the char to a file as base64 encoding
void write_b64(FILE *stream, const unsigned char *target, size_t length){
	if( stream == NULL ){lerror("Stream error: NULL reference\n"); return;} //unable to open stream
	char *enc;
	enc = b64_encode( target, length, BASE64_DEFAULT_WRAP);
	//enc = b64_encode( target, length, 0); //no wrapping
	fprintf(stream, "%s\n", enc );
	debug("Written %lu bytes with %lu b64 chars\n",length, b64_encoded_size(length, BASE64_DEFAULT_WRAP));
	free(enc);
}

//read a file completely
char *fileread(FILE *stream, size_t *length){
	if( stream == NULL ){lerror("Stream error: NULL reference\n"); return NULL;} //unable to open stream
	char *out;
	//obtain message size
	fseek(stream, 0, SEEK_END);
	*length = ftell(stream) + 1;
	fseek(stream, 0, SEEK_SET);  // same as rewind(f);

	if( *length < 1 ) return NULL; //invalid file

	out = (char *)malloc(*length); //allocate for message + null terminator
	fread(out, 1, *length-1, stream); //read all into buffer
	out[*length-1] = 0; //add null terminator
	return out;

}

//partial credits to Norman Ramsey
//https://stackoverflow.com/questions/3221170/how-to-turn-a-hex-string-into-an-unsigned-char-array
//converts a string s to an unsigned char array and store its length in length
unsigned char *hexstr2uc(const char *s, size_t *length) {
	if( strlen(s)%2 == 1 || strlen(s) < 0 ) return NULL; //must be even and positive
	size_t i; //counter1
	char p[3]; //the buffer to hold the currently processed byte
	size_t c = 0; //counter2
	size_t n = strlen(s)/2; //2 hex digits for each unsigned byte
	unsigned char *outbuf = (unsigned char *)malloc( n * sizeof( unsigned char ) );

	for (i=0; i< strlen(s); i+=2){
		p[0] = s[i];
		p[1] = s[i+1];
		p[2] = '\0'; //null terminator
		outbuf[c++] = strtoul( p, NULL, 16); //parse and save
	}
	*length = n; //save to length
	return outbuf; //return
}
