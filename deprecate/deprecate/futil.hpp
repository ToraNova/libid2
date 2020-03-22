/*
  File utility functions for the paircrypt project
  ToraNova 2019
  chia_jason96@live.com
*/
#ifndef _FUTIL_HPP_
#define _FUTIL_HPP_

#include <pbc/pbc.h>

namespace futil
{
	namespace bls{

		/* internals */
		//public file parser
		int _parse_pub_stream(FILE *stream,
			unsigned char **sysbuffer, size_t *sysn,
			unsigned char **pubbuffer, size_t *pubn
		);

		//secret file parser
		int _parse_sec_stream(FILE *stream,
			unsigned char **secbuffer, size_t *secn
		);

		//signature file parser
		int _parse_sig_stream(FILE *stream,
			unsigned char **sigbuffer, size_t *sign
		);

	}

	namespace bls_tight{

		/* internals */
		//public file parser
		int _parse_pub_stream(FILE *stream,
			unsigned char **g1buffer, size_t *g1n,
			unsigned char **g2buffer, size_t *g2n,
			unsigned char **x1buffer, size_t *x1n,
			unsigned char **x2buffer, size_t *x2n,
			unsigned char **ybuffer, size_t *yn
		);

		//secret file parser
		int _parse_sec_stream(FILE *stream,
			unsigned char **abuffer, size_t *an,
			unsigned char **bbuffer, size_t *bn
		);

		//signature file parser
		int _parse_sig_stream(FILE *stream,
			unsigned char **sigbuffer, size_t *sgsn, signed long int *urand
		);

	}

	//convert hex string to unsigned char array
	unsigned char *hexstr2uc(const char *s, size_t *length);
}


#endif
