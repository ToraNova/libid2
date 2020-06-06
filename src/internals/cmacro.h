/*
 * Constants and macro file
 * stores all defines here
 *
 * PLEASE DO NOT STORE CONFIGURATION MACROS, use autotools for that instead!
 *
 * ToraNova 2020
 * chia_jason96@live.com
 */

#ifndef _CMACRO_H_
#define _CMACRO_H_

// SIZES
// Ristretto255
#define RS_EPSZ crypto_core_ristretto255_BYTES
#define RS_SCSZ crypto_core_ristretto255_SCALARBYTES
#define RS_HSSZ crypto_core_ristretto255_HASHBYTES

// TCP socket
#define TS_MAXSZ 1024

// SIGNALS
//go-ahead
#define SIG_GA 0x5a



#endif

