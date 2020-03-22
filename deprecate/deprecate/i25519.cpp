/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
*/

// declaration includes
#include "i25519.hpp"
#include "ptdebug.h"

// implementation includes (archlinux os stored under /usr/include/sodium)
#include <sodium/crypto_sign.h>
#include <sodium/crypto_hash.h>
#include <sodium/crypto_scalarmult.h>

#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>

using namespace std;

namespace c25519
{
	//standard signatures
	namespace ss{

		int keygen(
			unsigned char **pbuffer, size_t *plen,
			unsigned char **sbuffer, size_t *slen
		){
			//creates pk,sk and creates the keypair
			*plen = crypto_sign_PUBLICKEYBYTES;
			*slen = crypto_sign_SECRETKEYBYTES;
			debug("PKSZ: %lu, SKSZ: %lu", *plen, *slen);
			*pbuffer = (unsigned char *)malloc( *(plen) );
			*sbuffer = (unsigned char *)malloc( *(slen) );
			int rc = crypto_sign_ed25519_keypair( *pbuffer, *sbuffer );

			//DEBUGGING
			//debug("KeyHex");
			//size_t i;
			//for(i=0;i<*plen;i++){
			//	printf("%02X", (*pbuffer)[i]);
			//}
			//printf("\n");
			//for(i=0;i<*slen;i++){
			//	printf("%02X", (*sbuffer)[i]);
			//}
			//printf("\n");
			///DEBUGGING

			return rc;
		}

		//vanilla implementation
		namespace vanilla{
			int sign(
				unsigned char *pbuffer, size_t plen,
				unsigned char *sbuffer, size_t slen,
				unsigned char *mbuffer, size_t mlen,
				unsigned char **obuffer, size_t *olen
			){
				size_t i; //counter
				unsigned char *full;

				//create memspace for signature
				*olen = mlen + crypto_sign_bytes();
				*obuffer = (unsigned char *)malloc(*olen);

				full = (unsigned char *)malloc(crypto_sign_SECRETKEYBYTES);
				for(i=0;i<slen;i++){
					full[i] = sbuffer[i];
				}
				for(i=0;i<plen;i++){
					full[i+slen] = pbuffer[i];
				}

				//DEBUGGING
				//for(i=0;i<crypto_sign_SECRETKEYBYTES;i++){
				//	printf("%02X", full[i]);
				//}
				//printf("\n");
				///DEBUGGING

				//create signature
				int rc = crypto_sign( *obuffer, NULL, mbuffer, mlen, full );
				debug("OSSZ: %lu, RC: %d",*olen,rc);
				free(full);
				return rc;
			}
			int verify(
				unsigned char *pbuffer, size_t plen,
				unsigned char *mbuffer, size_t mlen,
				unsigned char *obuffer, size_t olen
			){
				unsigned char *vmsg = (unsigned char *)malloc( olen );
				unsigned long long vlen; size_t i;
				unsigned long long mlenl = (unsigned long long) mlen;
				//"opens the signature implies decrypting it lol"

				//DEBUGGING
				//for(i=0;i<plen;i++){
				//	printf("%02X", pbuffer[i]);
				//}
				//printf("\n");
				///DEBUGGING

				int rc =  crypto_sign_open( vmsg, &vlen , obuffer, olen, pbuffer);
				if( rc != 0 ){
					//signature verification failed
					//possible causes: wrong public key
					return 1;
				}
				if( vlen != mlenl ){
					//signature verification failed
					//possible causes: invalid message (diff length)
					return 1;
				}
				for(i=0;i<vlen;i++){
					if( mbuffer[i] != vmsg [i] ){
						//signature verification failed
						//invalid byte
						return 1;
					}
				}
				debug("VMSZ: %llu, MSZ: %lu, RC: %d",vlen, mlen,rc);
				return rc;
			}
		}

		//custom implementation
		namespace id2{
			int sign(
				unsigned char *sbuffer, size_t slen,
				unsigned char *mbuffer, size_t mlen,
				unsigned char **obuffer, size_t *olen
			){
				//generate deterministic small r
				//unsigned char r[crypto_hash_sha512_BYTES];
				return 0;
			}

			int verify(
				unsigned char *pbuffer, size_t plen,
				unsigned char *mbuffer, size_t mlen,
				unsigned char *obuffer, size_t olen
			){

				return 0;
			}

		}

	}

	//IBI related functions
	namespace ibi{

	int setup(
		unsigned char **pbuffer, size_t *plen,
		unsigned char **sbuffer, size_t *slen
	){
		return ss::keygen(pbuffer,plen,sbuffer,slen);
	}

	int extract(
		unsigned char *pbuffer, size_t plen,
		unsigned char *sbuffer, size_t slen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char **obuffer, size_t *olen
	){
		return ss::id2::sign( sbuffer, slen, mbuffer, mlen, obuffer, olen );
	}

	/*
	 * Don't touch the following until security is proven
	 */
	int prove(
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen,
		int port, const char *srv,
		int timeout
	){
		return 0;

	}

	int verify(
		unsigned char *pbuffer, size_t plen,
		int port, int timeout
	){
		return 0;
	}

	int verifytest(
		unsigned char *pbuffer, size_t plen,
		unsigned char *mbuffer, size_t mlen,
		unsigned char *obuffer, size_t olen
	){
		return 0;
	}

	}
}
