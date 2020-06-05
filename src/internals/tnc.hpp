/*
 * TNC signature scheme key structure
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#define RS_EPSZ crypto_core_ristretto255_BYTES
#define RS_SCSZ crypto_core_ristretto255_SCALARBYTES
#define RS_HSSZ crypto_core_ristretto255_HASHBYTES

#include <stddef.h>

namespace tnc {

	struct pubkey{
		unsigned char *B;
		unsigned char *P1;
		unsigned char *P2;
	};

	struct seckey{
		unsigned char *a;
		struct pubkey *pub;
	};

	struct signat{
		//scalars
		unsigned char *s;
		unsigned char *x;
		//points
		unsigned char *U;
		unsigned char *V;
		unsigned char *B;
	};

	//randomly generate a key
	//return a key on success, null on error
	struct seckey *randomkey();

	//generate a signature based on a seckey and message
	//key - secret key used to sign message
	//mbuffer - buffer containing message to be signed
	//mlen - length of contents in mbuffer
	struct signat *signatgen(
		struct seckey *key,
		unsigned char *mbuffer, size_t mlen
	);

	//check a signature
	int signatchk(
		struct pubkey *par,
		struct signat *sig,
		unsigned char *mbuffer, size_t mlen
	);

	//serialize the secret,public and signature from a structure
	void secserial(struct seckey *in, unsigned char **sbuffer, size_t *slen);
	void pubserial(struct seckey *in, unsigned char **pbuffer, size_t *plen);
	void sigserial(struct signat *in, unsigned char **obuffer, size_t *olen);

	//creates a public key struct from the serialize string
	//inverse of secserial, pubserial and sigserial
	struct seckey *secstruct(unsigned char *sbuffer, size_t slen);
	struct pubkey *pubstruct(unsigned char *pbuffer, size_t plen);
	struct signat *sigstruct(unsigned char *obuffer, size_t olen);

	//destroy secret,public and signature struct
	void secdestroy(struct seckey *in);
	void pubdestroy(struct pubkey *in);
	void sigdestroy(struct signat *in);

	//print out key,signature structure (debugging use)
	void printsec(struct seckey *in);
	void printpub(struct pubkey *in);
	void printsig(struct signat *in);

}
