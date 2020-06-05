/*
 * TNC signature scheme key structure
 *
 * ToraNova 2020
 * chia_jason96@live.com
 *
 * this is for internal use only!
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C"{
#endif

	struct tnc_pubkey{
		unsigned char *B;
		unsigned char *P1;
		unsigned char *P2;
	};

	struct tnc_seckey{
		unsigned char *a;
		struct pubkey *pub;
	};

	struct tnc_signat{
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
	struct seckey *tnc_randomkey();

	//serialize the public key from the keystructure
	//return a non empty string on success, null on error
	unsigned char *tnc_pubserial(struct seckey *in);

	//serialize the secret key from the keystructure
	//return a non empty string on success, null on error
	unsigned char *tnc_secserial(struct seckey *in);

	//print out key structure (debugging use)
	void tnc_printkey(struct seckey *in);

	//creates a public key struct from the serialize string
	//inverse of pubserial
	struct pubkey *tnc_pubstruct(unsigned char *pbuffer, size_t plen);

	//inverse of secserial
	struct seckey *tnc_secstruct(unsigned char *sbuffer, size_t slen);

#ifdef __cplusplus
}
#endif

