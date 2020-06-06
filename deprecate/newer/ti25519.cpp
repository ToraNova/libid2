/*
 * An IBI scheme based off Ed25519
 * uses NaCl
 * https://nacl.cr.yp.to/install.html
 * Toranova2019
 * abbreviated as ti25519 - TNC identification using 25519
 *
*/

// declaration includes
#include "tsi25519.hpp"
#include "utils/debug.h"

#include "internals/proto.hpp"
#include "internals/tnc/proto.hpp"

//mini socket library
#include "utils/simplesock.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// implementation includes (archlinux os stored under /usr/include/sodium)
//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/randombytes.h>
//512bit hash (64byte)
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_verify_32.h>

// standard lib
#include <cstdlib>
#include <cstdio>
#include <string>
#include <time.h>

/*
 * Key storage detail (as of 2020 Mar 22)
 *
 * msk - < 256 a >< 256 B >< 256 P1 >< 256 P2 > (msk)
 * mpk - < 256 B >< 256 P1 >< 256 P2 > (mpk)
 * usk  - < 256 s >< 256 x >< 256 U >< 256 V >< 256 B > (does not need to store mpk anymore)
 *
 */
