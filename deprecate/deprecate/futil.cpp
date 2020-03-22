/*
 * File utils for the paircrypt project
 * ToraNova2019
*/

// file utils
#include "futil.hpp"
#include <cjson/cJSON.h> //for parsing
#include "ptdebug.h"
#include "jbase64.h"

// standard lib
#include <string>
#include <cstdlib>
#include <cstdio>

// parse buffer size
#define PARSEBUF_SZ 2048
#define STRNUM_BASE 10

using namespace std;
namespace futil
{
	namespace bls{

	//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS
	//return 0 on success and 1 on error
	int _parse_sig_stream(FILE *stream,
		unsigned char **sigbuffer, size_t *sgsn
	){
		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "signature");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{

			*sigbuffer = b64_decode( tmpr->valuestring );
			*sgsn = b64_decoded_size( tmpr->valuestring );

			//*sigbuffer = hexstr2uc( tmpr->valuestring, sgsn );
			if( *sigbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'signature'
			out = 1;
			goto end;
		}
		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

	//return 0 on success and 1 on error
	int _parse_pub_stream(FILE *stream,
		unsigned char **sysbuffer, size_t *sysn,
		unsigned char **pubbuffer, size_t *pubn
	){
		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "sys");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*sysbuffer = b64_decode( tmpr->valuestring );
			*sysn = b64_decoded_size( tmpr->valuestring );
			//*sysbuffer = hexstr2uc( tmpr->valuestring, sysn );
			if( *sysbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'sys'
			out = 1;
			goto end;
		}

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "pub");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*pubbuffer = b64_decode( tmpr->valuestring );
			*pubn = b64_decoded_size( tmpr->valuestring );
			//*pubbuffer = hexstr2uc( tmpr->valuestring, pubn );
			if( *pubbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'pub'
			out = 1;
			goto end;
		}

		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

	int _parse_sec_stream(FILE *stream,
		unsigned char **secbuffer, size_t *secn
	){
		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "secret");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{

			*secbuffer = b64_decode( tmpr->valuestring );
			*secn = b64_decoded_size( tmpr->valuestring );

			//*secbuffer = hexstr2uc( tmpr->valuestring, secn );
			if( *secbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'sec'
			out = 1;
			goto end;
		}

		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

	}

	namespace bls_tight{

	//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS//INTERNALS
	//return 0 on success and 1 on error
	int _parse_sig_stream(FILE *stream,
		unsigned char **sigbuffer, size_t *sgsn, signed long int *urand
	){
		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "signature");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*sigbuffer = hexstr2uc( tmpr->valuestring, sgsn );
			if( *sigbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'signature'
			out = 1;
			goto end;
		}

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "r");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			// TODO: parse r as a signed long int
			*urand = strtol( tmpr->valuestring, NULL,10 );
		} else {
			//parse error for 'r'
			out = 1;
			goto end;
		}


		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

	//return 0 on success and 1 on error
	//set g1n, g2n x1n x2n yn to null to skip them
	int _parse_pub_stream(FILE *stream,
		unsigned char **g1buffer, size_t *g1n,
		unsigned char **g2buffer, size_t *g2n,
		unsigned char **x1buffer, size_t *x1n,
		unsigned char **x2buffer, size_t *x2n,
		unsigned char **ybuffer, size_t *yn
	){

		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		if( g1n != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "g1");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*g1buffer = hexstr2uc( tmpr->valuestring, g1n );
			if( *g1buffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'g1'
			out = 1;
			goto end;
		}
		}

		if( g2n != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "g2");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*g2buffer = hexstr2uc( tmpr->valuestring, g2n );
			if( *g2buffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'g2'
			out = 1;
			goto end;
		}
		}

		if( x1n != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "x1");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*x1buffer = hexstr2uc( tmpr->valuestring, x1n );
			if( *x1buffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'x1'
			out = 1;
			goto end;
		}
		}

		if( x2n != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "x2");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*x2buffer = hexstr2uc( tmpr->valuestring, x2n );
			if( *x2buffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'x2'
			out = 1;
			goto end;
		}
		}

		if( yn != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "y");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*ybuffer = hexstr2uc( tmpr->valuestring, yn );
			if( *ybuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'y'
			out = 1;
			goto end;
		}
		}

		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

	int _parse_sec_stream(FILE *stream,
		unsigned char **abuffer, size_t *an,
		unsigned char **bbuffer, size_t *bn
	){
		cJSON *json, *tmpr=NULL;
		char *res;
		char tmpbuffer[PARSEBUF_SZ]; //readbuffer
		int out; //result code

		//read only one line
		res = fgets( tmpbuffer, PARSEBUF_SZ, stream);
		if( res == NULL ){
			//error occurred, nothing read
			return 1;
		}

		json = cJSON_Parse(tmpbuffer);
		if( json == NULL ){ out = 1; goto end; } //parse error

		tmpr = cJSON_GetObjectItemCaseSensitive(json, "a");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*abuffer = hexstr2uc( tmpr->valuestring, an );
			if( *abuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'sec'
			out = 1;
			goto end;
		}

		if( bn != NULL ){
		tmpr = cJSON_GetObjectItemCaseSensitive(json, "b");
		if (cJSON_IsString(tmpr) && (tmpr->valuestring != NULL))
		{
			*bbuffer = hexstr2uc( tmpr->valuestring, bn );
			if( *bbuffer == NULL ){ out = 2; goto end;} //conversion error
		} else {
			//parse error for 'sec'
			out = 1;
			goto end;
		}
		}

		out = 0;
end:
		//cleanup PLEASE DO THIS !
		cJSON_Delete(json);
		return out;
	}

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

}
