/*
 * A Signature scheme implementation for TNC tight signatures
 * based of Finite-field arithmetic over Curve25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 * abbreviated as ts25519 - TNC signature using 25519
 *
*/

// declaration includes
#include "tsi25519.hpp"
#include "utils/debug.h"
#include "utils/bufhelp.h"

//internals
#include "internals/proto.hpp"
#include "internals/tnc/static.hpp"
#include "internals/tnc/proto.hpp"

// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>

using namespace std;

namespace ts25519
{
	//standard signatures
	int keygen(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		//create a key structure
		struct tnc::seckey *key;
		//generate random key
		key = tnc::randomkey();
		if(key == NULL)return 1;

		//serialize the key to string
		tnc::secserial(key,sbuffer,slen);
		tnc::pubserial(key,pbuffer,plen);

#ifdef DEBUG
tnc::secprint(key);
printf("sbuffer %lu: ",*slen); ucbprint(*sbuffer, *slen); printf("\n");
printf("pbuffer %lu: ",*plen); ucbprint(*pbuffer, *plen); printf("\n");
#endif

		//clear the key
		secdestroy(key);

		return 0;
	}

	int sign(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		struct tnc::seckey *key;
		struct tnc::signat *sig;
		//obtain key from serialize string
		key = tnc::secstruct(sbuffer, slen);
		//signature generation
		sig = tnc::signatgen(key, mbuffer, mlen);

		//clear the secret key
		secdestroy(key);

		//serialize the signature to string
		tnc::sigserial(sig, obuffer, olen);

#ifdef DEBUG
sigprint(sig);
printf("obuffer %lu: ",*olen); ucbprint(*obuffer, *olen); printf("\n");
#endif

		//clear the signature
		sigdestroy(sig);

		return 0;
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		//obtain paramter (public key) and signature from serialize string
		struct tnc::pubkey *par;
		struct tnc::signat *sig;
		par = tnc::pubstruct(pbuffer, plen);
		sig = tnc::sigstruct(obuffer, olen);

		rc = signatchk(par, sig, mbuffer, mlen);

		sigdestroy(sig);
		pubdestroy(par);
		return rc;
	}
}

namespace ti25519{

	//IBI related functions
	int setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		return ts25519::keygen(pbuffer,plen,sbuffer,slen);
	}

	int extract(
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		return ts25519::sign( sbuffer, slen, mbuffer, mlen, obuffer, olen );
	}

	int prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int csock
	){
		if(csock == -1){
			lerror("Invalid socket\n");
			return 1;
		}

		int rc;
		//parse the usk
		struct tnc::signat *usk = tnc::sigstruct(obuffer, olen);

		debug("Sending ID string %s\n",mbuffer);
		rc = general::client::establish( csock, mbuffer, mlen );
		if(rc != 0){
			lerror("Failed to recv go-ahead (0x5a) byte\n");
			return 1;
		}
		debug("Go-Ahead received (0x5a), Starting PROVE protocol\n");

		rc = tnc::client::executeproto( csock, mbuffer, mlen, usk );

		//free up the usk
		tnc::sigdestroy(usk);
		return rc;
	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		unsigned char **mbuffer, size_t *mlen,
		int csock
	){
		if(csock == -1){
			lerror("Invalid socket\n");
			return 1;
		}

		int rc;
		//parse the params (public key)
		struct tnc::pubkey *par = tnc::pubstruct(pbuffer, plen);

		rc = general::server::establish( csock, mbuffer, mlen );
		if(rc != 0){
			lerror("Failed to recv ID from prover\n");
			return 1;
		}
		debug("Go-Ahead sent (0x5a), Starting VERIFY protocol\n");
		rc = tnc::server::executeproto( csock, *mbuffer, *mlen, par );

		//free up
		tnc::pubdestroy(par);
		return rc;
	}

	int verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		int rc;
		struct tnc::pubkey *par = tnc::pubstruct(pbuffer, plen);
		struct tnc::signat *usk = tnc::sigstruct(obuffer, olen);

		//run test
		rc = tnc::putest(par, usk, mbuffer, mlen);

		//clear out
		tnc::pubdestroy(par);
		tnc::sigdestroy(usk);

		return rc;
	}
}
