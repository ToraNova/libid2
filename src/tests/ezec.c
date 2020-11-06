/*
 * Curve25519/Ed25519 test suite
 * used for testing scalarmults of other implementation
 * and debugging
 *
 * Toranova 2020
 * chia_jason96@live.com
 */
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include "../utils/bufhelp.h"

/*
 * references
 * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
 * https://libsodium.gitbook.io/doc/
*/

int main(int argc, char *argv[]){
	int rc;
	char a[32];
	char b[32];
	char c[32];
	char d[32];
	char e[32];
	char big1[64];
	char big2[64];
	char sig[1024];
	size_t sz;
	unsigned long long dl;
	switch(argc){
		case 1:
			//no arg -- generate a ed25519 keypair
			crypto_sign_ed25519_keypair(a, big1);
			printf("pk (32): "); ucbprint(a, 32); printf("\n");
			printf("sk (64): "); ucbprint(big1, 64); printf("\n");

			//random a and obtain scalarmult with base a
			crypto_core_ed25519_scalar_random(a);
			printf("a  (32): "); ucbprint(a, 32); printf("\n");
			crypto_scalarmult_ed25519_base_noclamp(b,a);
			printf("aB (32): "); ucbprint(b, 32); printf("\n");
			crypto_scalarmult_ed25519_base(b,a);
			printf("aB'(32): "); ucbprint(b, 32); printf("\n");

		break;
		case 2:
			//1 arg, 1 byte 2 hex. 32 byte = 64 hex
			memcpy(big1, argv[1], 64);
			//convert hex to raw bytes
			//crypto_scalarmult_ed25519_noclamp
			hex2bin(a, big1, 64);
			printf("a  (32): "); ucbprint(a, 32); printf("\n");
			crypto_scalarmult_ed25519_base_noclamp(b,a);
			printf("aB (32): "); ucbprint(b, 32); printf("\n");
			crypto_scalarmult_ed25519_base(b,a);
			printf("aB'(32): "); ucbprint(b, 32); printf("\n");

			//treat a as seed
			crypto_hash_sha512(c, a, 32);
			c[0] &= 248;
			c[31] &= 127;
			c[31] |= 64;
			crypto_scalarmult_ed25519_base_noclamp(b,c);
			printf("sd (32): "); ucbprint(b, 32); printf("\n");
			crypto_scalarmult_ed25519_base(b,c);
			printf("sd'(32): "); ucbprint(b, 32); printf("\n");

		break;
		case 3:
			//2 args
			memcpy(big1, argv[1], 64);
			hex2bin(a, big1, 64);
			sz = strlen(argv[2]);
			//arg 1 is seed, arg 2 is message to be signed
			crypto_sign_ed25519(sig, &dl, argv[2], sz, a);
			printf("sig(%lu): ",dl); ucbprint(sig, dl); printf("\n");
		case 4:
			//3 args
			memcpy(big1, argv[1], 64);
			hex2bin(a, big1, 64);

			memcpy(big2, argv[2], 64);
			hex2bin(b, big2, 64);

			sz = strlen(argv[3]);

			// compute hash(R,A,id) (R,A,M)
			// perform RAM hash from ref10 implementation
			crypto_hash_sha512_state hs;
			crypto_hash_sha512_init(&hs); //no prehash
			crypto_hash_sha512_update(&hs, a, 32);
			crypto_hash_sha512_update(&hs, b, 32);
			crypto_hash_sha512_update(&hs, argv[3] , sz);
			crypto_hash_sha512_final( &hs, big1 );
			crypto_core_ed25519_scalar_reduce(c, big1); //reduce to scalar
			printf("hram   : "); ucbprint(c, 32); printf("\n");
			printf("b      : "); ucbprint(b, 32); printf("\n");

			//exp
			/*
			rc = 0;
			rc += crypto_scalarmult_ed25519_noclamp(d, c, b);
			rc += crypto_scalarmult_ed25519_base_noclamp(e, c);
			rc += crypto_core_ed25519_add(d, e, d);
			printf("exp(%2d): ",rc); ucbprint(d, 32); printf("\n");
			*/

			// xert(A|B) = A|B + hram Sigma where Sigma = kgcpub
			rc = crypto_scalarmult_ed25519_noclamp(d, c, b);
			rc = crypto_core_ed25519_add(d, a, d);
			printf("xrt(%2d): ",rc); ucbprint(d, 32); printf("\n");
		break;
		default:
			printf("invalid arguments");
	}
}


