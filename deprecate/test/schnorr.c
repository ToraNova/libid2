/*
 * A SchnorrSuite Implementation using Curve25519
 * https://nacl.cr.yp.to/scalarmult.html
 * This is an implementation of the Schnorr Identity-based Identification
 * however, instead than using JAVA Big Integer,
 * Scalar Multiplication on Curve25519 is used instead.
 *
 * This is a test file. The full library is still in development!
 *
 * Written by ToraNova
 * chia_jason96@live.com
 */

//the following included for typedef of uint32_t (32bit block)
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <ptdebug.h>

//Nacl Finite Field Arithmetic on top of Curve25519
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/randombytes.h>
//512bit hash (64byte)
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_verify_32.h>

#define RLIMIT 100
/*
int schnorr(const unsigned char *id, size_t ilen){
	int out;
	size_t i,c;

	//---------------------------------------------------------------------------------
	//setup
	//---------------------------------------------------------------------------------
	unsigned char x_sc[crypto_core_ristretto255_SCALARBYTES]; //secret
	unsigned char n_sc[crypto_core_ristretto255_SCALARBYTES]; //negative of x
	unsigned char y_el[crypto_core_ristretto255_BYTES]; //y1
	unsigned char b_el[crypto_core_ristretto255_BYTES]; //base point B

	//debugging lines
	clock_t start, end;
	double cpu_time_used;
	start = clock();

	//generate random 32bit scalar Zq
	crypto_core_ristretto255_scalar_random(x_sc);

	//perform base multiplication y = -xB (y = g^-x)
	//mpk is y and msk is x
	crypto_core_ristretto255_scalar_negate( n_sc, x_sc);
	crypto_scalarmult_ristretto255_base(y_el, n_sc);

	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("setup t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//extract
	//---------------------------------------------------------------------------------
	unsigned char t_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char o_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char a_el[crypto_core_ristretto255_BYTES];
	unsigned char o_el[crypto_core_ristretto255_BYTES];
	unsigned char a_hs[crypto_core_ristretto255_HASHBYTES];

	//debugging lines
	start = clock();

	for(c=0;c<RLIMIT;c++){

		//generate nonce
		//randombytes_buf(t_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(t_sc);

		//create usk pub
		crypto_scalarmult_ristretto255_base( a_el, t_sc);

		//compute hash
		crypto_hash_sha512_state eh_state;
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, id, ilen);
		crypto_hash_sha512_update( &eh_state, a_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, y_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &eh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( o_sc, o_el);

		//compute s
		// tmp = x_sc * o_sc
		crypto_core_ristretto255_scalar_mul( tmp, x_sc, o_sc );
		// s_sc = tmp + t_sc
		// usk is ( o_sc, s_sc )
		crypto_core_ristretto255_scalar_add( s_sc, t_sc, tmp );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("extract t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//identification
	//---------------------------------------------------------------------------------
	unsigned char cha_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char cmt_el0[crypto_core_ristretto255_BYTES];
	unsigned char v_el1[crypto_core_ristretto255_BYTES];
	unsigned char v_el2[crypto_core_ristretto255_BYTES];
	unsigned char cap_A[crypto_core_ristretto255_BYTES];
	unsigned char LHS[crypto_core_ristretto255_BYTES];
	unsigned char RHS[crypto_core_ristretto255_BYTES];

	//precomputation
	//compute v_el2 = y_el ^ o_sc
	crypto_scalarmult_ristretto255( v_el2, o_sc, y_el);
	crypto_scalarmult_ristretto255_base( v_el1, s_sc );
	crypto_core_ristretto255_add( cap_A, v_el1, v_el2 );
	//cmt_el0 and cap_A is sent to V

	start = clock();

	for(c=0;c<RLIMIT;c++){
		//P compute commit
		crypto_core_ristretto255_scalar_random(non_sc);
		crypto_scalarmult_ristretto255_base( cmt_el0, non_sc);


		//obtain challenge
		crypto_core_ristretto255_scalar_random(cha_sc);

		//response
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s_sc );
		crypto_core_ristretto255_scalar_add( rsp_sc, non_sc, tmp );

		//validation
		crypto_scalarmult_ristretto255_base( LHS, rsp_sc ); //tmp use
		crypto_scalarmult_ristretto255( v_el2, o_sc, y_el); //assume v computes o_sc = H(ID, A, y1)
		crypto_core_ristretto255_sub( v_el1, cap_A, v_el2 ); // v_el1 = cap_A - v_el2
		crypto_scalarmult_ristretto255( v_el2, cha_sc, v_el1); // v_el2 = v_el1 ^ cha_sc
		crypto_core_ristretto255_add( RHS, cmt_el0, v_el2 );

		out = crypto_verify_32( LHS, RHS );
		//for(i=0;i<crypto_core_ristretto255_BYTES;i++){
		//	if( LHS[i] != RHS[i] ){
		//		return 1;
		//	}
		//}
	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("ident t: %f ms", cpu_time_used/RLIMIT );

	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",LHS[i]); }printf("\n");
	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",RHS[i]); }printf("\n");

	return out;
}

int tight(const unsigned char *id, size_t ilen){
	int out;
	size_t i,c;
	//---------------------------------------------------------------------------------
	//setup
	//---------------------------------------------------------------------------------
	unsigned char x_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char n_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x
	unsigned char y1_el[crypto_core_ristretto255_BYTES];
	unsigned char y2_el[crypto_core_ristretto255_BYTES];
	unsigned char h_el[crypto_core_ristretto255_BYTES];

	//debugging lines
	clock_t start, end;
	double cpu_time_used;
	start = clock();

	for(c=0;c<RLIMIT;c++){
		//generate random 32bit Zq
		//randombytes_buf(x_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(x_sc);
		crypto_core_ristretto255_random(h_el);

		//perform base multiplication y = -xB (y = g^-x)
		//mpk is y and msk is x
		crypto_core_ristretto255_scalar_negate( n_sc, x_sc);
		crypto_scalarmult_ristretto255_base(y1_el, n_sc);
		crypto_scalarmult_ristretto255(y2_el, n_sc, h_el);

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("setup t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//extract
	//---------------------------------------------------------------------------------
	unsigned char t_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char o_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char a_el[crypto_core_ristretto255_BYTES];
	unsigned char b_el[crypto_core_ristretto255_BYTES];
	unsigned char o_el[crypto_core_ristretto255_BYTES];
	unsigned char a_hs[crypto_core_ristretto255_HASHBYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){
		//generate nonce
		//randombytes_buf(t_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(t_sc);

		//create usk pub
		crypto_scalarmult_ristretto255_base( a_el, t_sc);
		crypto_scalarmult_ristretto255( b_el, t_sc, h_el);

		//compute hash
		crypto_hash_sha512_state eh_state;
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, id, ilen);
		crypto_hash_sha512_update( &eh_state, a_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, b_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, y1_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, y2_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &eh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( o_sc, o_el);

		//compute s
		// tmp = x_sc * o_sc
		crypto_core_ristretto255_scalar_mul( tmp, x_sc, o_sc );
		// s_sc = tmp + t_sc
		// usk is ( o_sc, s_sc )
		crypto_core_ristretto255_scalar_add( s_sc, t_sc, tmp );
	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("extract t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//identification
	//---------------------------------------------------------------------------------
	unsigned char cha_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char cmt_el0[crypto_core_ristretto255_BYTES];
	unsigned char v_el1[crypto_core_ristretto255_BYTES];
	unsigned char v_el2[crypto_core_ristretto255_BYTES];
	unsigned char cap_A[crypto_core_ristretto255_BYTES];
	unsigned char cap_B[crypto_core_ristretto255_BYTES];
	unsigned char LHS[crypto_core_ristretto255_BYTES];
	unsigned char RHS[crypto_core_ristretto255_BYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){
		//P compute commit
		crypto_core_ristretto255_scalar_random(non_sc);
		crypto_scalarmult_ristretto255_base( cmt_el0, non_sc);

		//compute cap_A = g^s_sc y1_el ^ o_sc
		crypto_scalarmult_ristretto255( v_el2, o_sc, y1_el);
		crypto_scalarmult_ristretto255_base( v_el1, s_sc );
		crypto_core_ristretto255_add( cap_A, v_el1, v_el2 );

		//compute cap_B = h_el^s_sc y2_el ^ o_sc
		crypto_scalarmult_ristretto255( v_el2, o_sc, y2_el);
		crypto_scalarmult_ristretto255( v_el1, s_sc, h_el );
		crypto_core_ristretto255_add( cap_B, v_el1, v_el2 );
		//cmt_el0, cap_A and cap_B is sent to V

		//obtain challenge
		crypto_core_ristretto255_scalar_random(cha_sc);

		//response
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s_sc );
		crypto_core_ristretto255_scalar_add( rsp_sc, non_sc, tmp );

		//validation
		crypto_scalarmult_ristretto255_base( LHS, rsp_sc ); //tmp use
		crypto_scalarmult_ristretto255( v_el2, o_sc, y1_el); //assume v computes o_sc = H(ID, A, y1)
		crypto_core_ristretto255_sub( v_el1, cap_A, v_el2 ); // v_el1 = cap_A - v_el2
		crypto_scalarmult_ristretto255( v_el2, cha_sc, v_el1); // v_el2 = v_el1 ^ cha_sc
		crypto_core_ristretto255_add( RHS, cmt_el0, v_el2 );

		out = crypto_verify_32( LHS, RHS );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("ident t: %f ms", cpu_time_used/RLIMIT );

	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",LHS[i]); }printf("\n");
	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",RHS[i]); }printf("\n");

	return out;
}

int twin(const unsigned char *id, size_t ilen){
	int out;
	size_t i,c;
	//---------------------------------------------------------------------------------
	//setup
	//---------------------------------------------------------------------------------
	unsigned char x1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char x2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char n1_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x1
	unsigned char n2_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x2
	unsigned char y1_el[crypto_core_ristretto255_BYTES];
	unsigned char y2_el[crypto_core_ristretto255_BYTES];
	unsigned char x_el[crypto_core_ristretto255_BYTES];
	unsigned char h_el[crypto_core_ristretto255_BYTES];

	//debugging lines
	clock_t start, end;
	double cpu_time_used;

	start = clock();
	for(c=0;c<RLIMIT;c++){
		//generate random 32bit Zq
		//randombytes_buf(x_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(x1_sc);
		crypto_core_ristretto255_scalar_random(x2_sc);
		crypto_core_ristretto255_random(h_el);

		//perform base multiplication y = -xB (y = g^-x)
		//mpk is y and msk is x
		crypto_core_ristretto255_scalar_negate( n1_sc, x1_sc);
		crypto_core_ristretto255_scalar_negate( n2_sc, x2_sc);
		crypto_scalarmult_ristretto255_base(y1_el, n1_sc);
		crypto_scalarmult_ristretto255(y2_el, n2_sc, h_el);
		crypto_core_ristretto255_add( x_el, y1_el, y2_el );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("setup t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//extract
	//---------------------------------------------------------------------------------
	unsigned char t1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char t2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char o_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char a_el[crypto_core_ristretto255_BYTES];
	unsigned char b_el[crypto_core_ristretto255_BYTES];
	unsigned char o_el[crypto_core_ristretto255_BYTES];
	unsigned char r_el[crypto_core_ristretto255_BYTES];
	unsigned char a_hs[crypto_core_ristretto255_HASHBYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//generate nonce
		//randombytes_buf(t_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(t1_sc);
		crypto_core_ristretto255_scalar_random(t2_sc);

		//create usk pub
		crypto_scalarmult_ristretto255_base( a_el, t1_sc);
		crypto_scalarmult_ristretto255( b_el, t2_sc, h_el);
		crypto_core_ristretto255_add( r_el, a_el, b_el);

		//compute hash
		crypto_hash_sha512_state eh_state;
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, id, ilen);
		crypto_hash_sha512_update( &eh_state, r_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, x_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &eh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( o_sc, o_el);

		//compute s1
		// tmp = x_sc * o_sc
		crypto_core_ristretto255_scalar_mul( tmp, x1_sc, o_sc );
		// s_sc = tmp + t_sc
		crypto_core_ristretto255_scalar_add( s1_sc, t1_sc, tmp );

		crypto_core_ristretto255_scalar_mul( tmp, x2_sc, o_sc );
		crypto_core_ristretto255_scalar_add( s2_sc, t2_sc, tmp );
		// s1_sc, s2_sc and o_sc are usk

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("extract t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//identification
	//---------------------------------------------------------------------------------
	unsigned char cha_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char cmt_el0[crypto_core_ristretto255_BYTES];
	unsigned char v_el1[crypto_core_ristretto255_BYTES];
	unsigned char v_el2[crypto_core_ristretto255_BYTES];
	unsigned char v_el3[crypto_core_ristretto255_BYTES];
	unsigned char cap_A[crypto_core_ristretto255_BYTES];
	unsigned char cap_B[crypto_core_ristretto255_BYTES];
	unsigned char LHS[crypto_core_ristretto255_BYTES];
	unsigned char RHS[crypto_core_ristretto255_BYTES];

	//precomputation
	crypto_scalarmult_ristretto255( cap_A, o_sc, x_el);
	crypto_scalarmult_ristretto255_base( v_el1, s1_sc );
	crypto_scalarmult_ristretto255( v_el2, s2_sc, h_el);
	crypto_core_ristretto255_add( v_el3, v_el1, v_el2  );
	crypto_core_ristretto255_add( cap_B, cap_A, v_el3 );

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//P compute commit
		crypto_core_ristretto255_scalar_random(non1_sc);
		crypto_core_ristretto255_scalar_random(non2_sc);

		crypto_scalarmult_ristretto255_base( v_el1, non1_sc);
		crypto_scalarmult_ristretto255( v_el2, non2_sc, h_el);
		crypto_core_ristretto255_add( cmt_el0, v_el1, v_el2 );

		//compute cap_A = g^s_sc y1_el ^ o_sc
		//sends cap_B and cmt_el0

		//obtain challenge
		crypto_core_ristretto255_scalar_random(cha_sc);

		//response
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s1_sc );
		crypto_core_ristretto255_scalar_add( rsp1_sc, non1_sc, tmp );
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s2_sc );
		crypto_core_ristretto255_scalar_add( rsp2_sc, non2_sc, tmp );

		//validation
		crypto_scalarmult_ristretto255_base( v_el1, rsp1_sc );
		crypto_scalarmult_ristretto255( v_el2, rsp2_sc, h_el );
		crypto_core_ristretto255_add( LHS, v_el1, v_el2 );

		crypto_scalarmult_ristretto255( v_el2, o_sc, x_el); //assume v computes o_sc = H(ID, A, y1)
		crypto_core_ristretto255_sub( v_el1, cap_B, v_el2 ); // v_el1 = cap_B - v_el2
		crypto_scalarmult_ristretto255( v_el2, cha_sc, v_el1); // v_el2 = v_el1 ^ cha_sc
		crypto_core_ristretto255_add( RHS, cmt_el0, v_el2 );

		out = crypto_verify_32( LHS, RHS );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("ident t: %f ms", cpu_time_used/RLIMIT );

	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",LHS[i]); }printf("\n");
	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",RHS[i]); }printf("\n");
	return out;
}

int reset(const unsigned char *id, size_t ilen){
	int out;
	size_t i,c;
	//---------------------------------------------------------------------------------
	//setup
	//---------------------------------------------------------------------------------
	unsigned char x_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char z_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char n_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x
	unsigned char y_el[crypto_core_ristretto255_BYTES];
	unsigned char h_el[crypto_core_ristretto255_BYTES];

	//debugging lines
	clock_t start, end;
	double cpu_time_used;

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//generate random 32bit Zq
		//randombytes_buf(x_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(x_sc);
		crypto_core_ristretto255_scalar_random(z_sc);

		//perform base multiplication y = -xB (y = g^-x)
		//msk is x,a
		crypto_core_ristretto255_scalar_negate( n_sc, x_sc);
		crypto_scalarmult_ristretto255_base(y_el, n_sc);
		crypto_scalarmult_ristretto255_base(h_el, z_sc);

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("setup t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//extract
	//---------------------------------------------------------------------------------
	unsigned char t_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char o_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char a_el[crypto_core_ristretto255_BYTES];
	unsigned char o_el[crypto_core_ristretto255_BYTES];
	unsigned char a_hs[crypto_core_ristretto255_HASHBYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//generate nonce
		//randombytes_buf(t_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(t_sc);

		//create usk pub
		crypto_scalarmult_ristretto255_base( a_el, t_sc);

		//compute hash
		crypto_hash_sha512_state eh_state;
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, id, ilen);
		crypto_hash_sha512_update( &eh_state, a_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, y_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &eh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( o_sc, o_el);

		//compute s
		// tmp = x_sc * o_sc
		crypto_core_ristretto255_scalar_mul( tmp, x_sc, o_sc );
		// s_sc = tmp + t_sc
		// usk is ( o_sc, s_sc )
		crypto_core_ristretto255_scalar_add( s_sc, t_sc, tmp );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("extract t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//identification
	//---------------------------------------------------------------------------------
	unsigned char cha_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char cmt_cp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char pre_el[crypto_core_ristretto255_BYTES];
	unsigned char cmt_el0[crypto_core_ristretto255_BYTES];
	unsigned char v_el1[crypto_core_ristretto255_BYTES];
	unsigned char v_el2[crypto_core_ristretto255_BYTES];
	unsigned char cap_A[crypto_core_ristretto255_BYTES];
	unsigned char cap_B[crypto_core_ristretto255_BYTES];
	unsigned char LHS[crypto_core_ristretto255_BYTES];
	unsigned char RHS[crypto_core_ristretto255_BYTES];
	unsigned char PC[crypto_core_ristretto255_BYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//V compute c first
		crypto_core_ristretto255_scalar_random(non_sc); //r
		crypto_core_ristretto255_scalar_random(cha_sc); //m
		crypto_scalarmult_ristretto255_base( v_el1, cha_sc );
		crypto_scalarmult_ristretto255( v_el2, non_sc, h_el );
		crypto_core_ristretto255_add( pre_el, v_el1, v_el2 ); //compute pre-nonce

		//compute hash
		randombytes_buf(PC, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_state vh_state;
		crypto_hash_sha512_init( &vh_state );
		crypto_hash_sha512_update( &vh_state, PC, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &vh_state, pre_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &vh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( cmt_cp, o_el);

		//compute v_el2 = y_el ^ o_sc
		crypto_scalarmult_ristretto255_base( cap_A, cmt_cp );
		crypto_scalarmult_ristretto255( v_el2, o_sc, y_el);
		crypto_scalarmult_ristretto255_base( v_el1, s_sc );
		crypto_core_ristretto255_add( cap_B, v_el1, v_el2 );
		//cap_A and cap_B is sent to V

		//sends non_sc and cha_sc

		//proceed iff c = g^cha_sc . h_el^non_sc
		crypto_core_ristretto255_scalar_reduce( cha_sc, pre_el);

		//response
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s_sc );
		crypto_core_ristretto255_scalar_add( rsp_sc, cmt_cp, tmp );

		//validation
		crypto_scalarmult_ristretto255_base( LHS, rsp_sc ); //tmp use
		crypto_scalarmult_ristretto255( v_el2, o_sc, y_el); //assume v computes o_sc = H(ID, A, y1)
		crypto_core_ristretto255_sub( v_el1, cap_B, v_el2 ); // v_el1 = cap_A - v_el2
		crypto_scalarmult_ristretto255( v_el2, cha_sc, v_el1); // v_el2 = v_el1 ^ cha_sc
		crypto_core_ristretto255_add( RHS, cap_A, v_el2 );


		out = crypto_verify_32( LHS, RHS );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("ident t: %f ms", cpu_time_used/RLIMIT );

	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",LHS[i]); }printf("\n");
	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",RHS[i]); }printf("\n");
	return out;
}

int reset2(const unsigned char *id, size_t ilen){
	int out;
	size_t i,c;
	//---------------------------------------------------------------------------------
	//setup
	//---------------------------------------------------------------------------------
	unsigned char x1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char x2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char n1_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x1
	unsigned char n2_sc[crypto_core_ristretto255_SCALARBYTES]; //negativ of x2
	unsigned char z_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char y1_el[crypto_core_ristretto255_BYTES];
	unsigned char y2_el[crypto_core_ristretto255_BYTES];
	unsigned char x_el[crypto_core_ristretto255_BYTES];
	unsigned char h_el[crypto_core_ristretto255_BYTES];
	unsigned char rs_el[crypto_core_ristretto255_BYTES];

	//debugging lines
	clock_t start, end;
	double cpu_time_used;

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//generate random 32bit Zq
		//randombytes_buf(x_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(x1_sc);
		crypto_core_ristretto255_scalar_random(x2_sc);
		crypto_core_ristretto255_scalar_random(z_sc);
		crypto_core_ristretto255_random(h_el);

		//perform base multiplication y = -xB (y = g^-x)
		//mpk is y and msk is x
		crypto_core_ristretto255_scalar_negate( n1_sc, x1_sc);
		crypto_core_ristretto255_scalar_negate( n2_sc, x2_sc);
		crypto_scalarmult_ristretto255_base(y1_el, n1_sc);
		crypto_scalarmult_ristretto255(y2_el, n2_sc, h_el);
		crypto_core_ristretto255_add( x_el, y1_el, y2_el ); //capital X
		crypto_scalarmult_ristretto255_base(rs_el, z_sc); //h

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("setup t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//extract
	//---------------------------------------------------------------------------------
	unsigned char t1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char t2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char s2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char o_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char tmp[crypto_core_ristretto255_SCALARBYTES];
	unsigned char a_el[crypto_core_ristretto255_BYTES];
	unsigned char b_el[crypto_core_ristretto255_BYTES];
	unsigned char o_el[crypto_core_ristretto255_BYTES];
	unsigned char r_el[crypto_core_ristretto255_BYTES];
	unsigned char a_hs[crypto_core_ristretto255_HASHBYTES];

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//generate nonce
		//randombytes_buf(t_sc,crypto_core_ristretto255_SCALARBYTES);
		crypto_core_ristretto255_scalar_random(t1_sc);
		crypto_core_ristretto255_scalar_random(t2_sc);

		//create usk pub
		crypto_scalarmult_ristretto255_base( a_el, t1_sc);
		crypto_scalarmult_ristretto255( b_el, t2_sc, h_el);
		crypto_core_ristretto255_add( r_el, a_el, b_el);

		//compute hash
		crypto_hash_sha512_state eh_state;
		crypto_hash_sha512_init( &eh_state );
		crypto_hash_sha512_update( &eh_state, id, ilen);
		crypto_hash_sha512_update( &eh_state, r_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_update( &eh_state, x_el, crypto_core_ristretto255_BYTES);
		crypto_hash_sha512_final( &eh_state, a_hs);
		crypto_core_ristretto255_from_hash( o_el , (const unsigned char *)a_hs );
		//o_el is an element, we perform reduction into a scalar
		crypto_core_ristretto255_scalar_reduce( o_sc, o_el);

		//compute s1
		// tmp = x_sc * o_sc
		crypto_core_ristretto255_scalar_mul( tmp, x1_sc, o_sc );
		// s_sc = tmp + t_sc
		crypto_core_ristretto255_scalar_add( s1_sc, t1_sc, tmp );

		crypto_core_ristretto255_scalar_mul( tmp, x2_sc, o_sc );
		crypto_core_ristretto255_scalar_add( s2_sc, t2_sc, tmp );
		// s1_sc, s2_sc and o_sc are usk

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("extract t: %f ms", cpu_time_used/RLIMIT );

	//---------------------------------------------------------------------------------
	//identification
	//---------------------------------------------------------------------------------
	unsigned char cha_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char rsp2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non1_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non2_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char non3_sc[crypto_core_ristretto255_SCALARBYTES];
	unsigned char pre_el[crypto_core_ristretto255_BYTES];
	unsigned char cmt_el0[crypto_core_ristretto255_BYTES];
	unsigned char v_el1[crypto_core_ristretto255_BYTES];
	unsigned char v_el2[crypto_core_ristretto255_BYTES];
	unsigned char v_el3[crypto_core_ristretto255_BYTES];
	unsigned char cap_A[crypto_core_ristretto255_BYTES];
	unsigned char cap_B[crypto_core_ristretto255_BYTES];
	unsigned char LHS[crypto_core_ristretto255_BYTES];
	unsigned char RHS[crypto_core_ristretto255_BYTES];
	unsigned char PC[crypto_core_ristretto255_BYTES];

	//precomputation
	crypto_scalarmult_ristretto255( cap_A, o_sc, x_el);
	crypto_scalarmult_ristretto255_base( v_el1, s1_sc );
	crypto_scalarmult_ristretto255( v_el2, s2_sc, h_el);
	crypto_core_ristretto255_add( v_el3, v_el1, v_el2  );
	crypto_core_ristretto255_add( cap_B, cap_A, v_el3 );

	start = clock();
	for(c=0;c<RLIMIT;c++){

		//P compute commit
		crypto_core_ristretto255_scalar_random(non1_sc); //this is r
		crypto_core_ristretto255_scalar_random(cha_sc); //this is m

		crypto_scalarmult_ristretto255_base( v_el1, cha_sc);
		crypto_scalarmult_ristretto255( v_el2, non1_sc, rs_el);
		crypto_core_ristretto255_add( pre_el, v_el1, v_el2 );

		//compute hash
		//use SHA512 for faster runtimes (refer RS-schnorr)
		crypto_core_ristretto255_scalar_random(non3_sc);
		crypto_scalarmult_ristretto255( v_el2, non3_sc, pre_el);
		crypto_core_ristretto255_scalar_reduce( non1_sc, v_el2);
		crypto_core_ristretto255_scalar_random(non3_sc);
		crypto_scalarmult_ristretto255( v_el2, non3_sc, pre_el);
		crypto_core_ristretto255_scalar_reduce( non2_sc, v_el2);

		crypto_scalarmult_ristretto255_base( v_el1, non1_sc);
		crypto_scalarmult_ristretto255( v_el2, non2_sc, h_el);
		crypto_core_ristretto255_add( cmt_el0, v_el1, v_el2 );

		//compute cap_A = g^s_sc y1_el ^ o_sc
		//sends cap_B and cmt_el0

		//obtain challenge
		crypto_core_ristretto255_scalar_random(cha_sc);

		//response
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s1_sc );
		crypto_core_ristretto255_scalar_add( rsp1_sc, non1_sc, tmp );
		crypto_core_ristretto255_scalar_mul( tmp, cha_sc, s2_sc );
		crypto_core_ristretto255_scalar_add( rsp2_sc, non2_sc, tmp );

		//validation
		crypto_scalarmult_ristretto255_base( v_el1, rsp1_sc );
		crypto_scalarmult_ristretto255( v_el2, rsp2_sc, h_el );
		crypto_core_ristretto255_add( LHS, v_el1, v_el2 );

		crypto_scalarmult_ristretto255( v_el2, o_sc, x_el); //assume v computes o_sc = H(ID, A, y1)
		crypto_core_ristretto255_sub( v_el1, cap_B, v_el2 ); // v_el1 = cap_B - v_el2
		crypto_scalarmult_ristretto255( v_el2, cha_sc, v_el1); // v_el2 = v_el1 ^ cha_sc
		crypto_core_ristretto255_add( RHS, cmt_el0, v_el2 );

		out = crypto_verify_32( LHS, RHS );

	}
	end = clock();
	cpu_time_used = ((((double) (end - start)) / CLOCKS_PER_SEC) * 1000); //millis
	debug("ident t: %f ms", cpu_time_used/RLIMIT );

	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",LHS[i]); }printf("\n");
	for(i=0;i<crypto_core_ristretto255_BYTES;i++){ printf("%02X",RHS[i]); }printf("\n");
	return out;
}

//main runner
int main(int argc, char *argv[]){
	int rc;
	const unsigned char id[] = "chia_jason96@live.com";
	verbose("running kh-schnorr-ibi");
	rc = schnorr( id, sizeof(id) );
	if(rc){
		log_info("-");
	}else{
		log_info("+");
	}
	verbose("running tight-schnorr-ibi");
	rc = tight( id, sizeof(id) );
	if(rc){
		log_info("-");
	}else{
		log_info("+");
	}

	verbose("running twin-schnorr-ibi");
	rc = twin( id, sizeof(id) );
	if(rc){
		log_info("-");
	}else{
		log_info("+");
	}

	verbose("running reset-schnorr-ibi");
	rc = reset( id, sizeof(id) );
	if(rc){
		log_info("-");
	}else{
		log_info("+");
	}

	verbose("running reset-twin-schnorr-ibi");
	rc = reset2( id, sizeof(id) );
	if(rc){
		log_info("-");
	}else{
		log_info("+");
	}
	return 0;
}
*/

int main(){
	return 0;
}
