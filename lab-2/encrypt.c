/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

typedef uint8_t aes_gf28_t;

aes_gf28_t aes_gf28_inv(aes_gf28_t a);
aes_gf28_t aes_gf28_add ( aes_gf28_t a, aes_gf28_t b );
aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b );
aes_gf28_t xtime( aes_gf28_t a );
aes_gf28_t sbox( aes_gf28_t a );
void aes_enc_keyexp_step ( aes_gf28_t* r, const aes_gf28_t* rk , aes_gf28_t rc );
void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk );
void aes_enc_rnd_sub( aes_gf28_t* s );
void aes_enc_rnd_row( aes_gf28_t* s );
void aes_enc_rnd_mix( aes_gf28_t* s );
void aes_enc(uint8_t* m, uint8_t* k, aes_gf28_t* c );


int main( int argc, char* argv[] ) {
  aes_gf28_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  aes_gf28_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
  aes_gf28_t c[ 16 ];

  aes_enc(m, k, c);

  for (int x = 0; x < 16; x++) {
    printf("%x, ", c[x]);
  }
  printf("\n");

}
void aes_enc( aes_gf28_t* m, aes_gf28_t* k, aes_gf28_t* c ) {
  
  aes_gf28_t* rkp = k;

  const aes_gf28_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  memcpy(c, m, 16);
  aes_enc_rnd_key(c, k);
  for (int i = 1; i <= 9; i++) {
    aes_enc_rnd_sub( c );
    aes_enc_rnd_row( c );
    aes_enc_rnd_mix(c);
    aes_enc_keyexp_step ( rkp , rkp , RC[i-1] );
    aes_enc_rnd_key(c, rkp);
  }
  aes_enc_rnd_sub( c );
  aes_enc_rnd_row( c );
  aes_enc_keyexp_step ( rkp , rkp , RC[9] );
  aes_enc_rnd_key(c, rkp);

  
}

void aes_enc_rnd_row( aes_gf28_t* m ) {

  aes_gf28_t hold[16];
  memcpy(hold, m, 16);
  m[1] = hold[5];
  m[5] = hold[9];
  m[9] = hold[13];
  m[13] = hold[1];

  m[2] = hold[10];
  m[6] = hold[14];
  m[10] = hold[2];
  m[14] = hold[6];

  m[3] = hold[15];
  m[7] = hold[3];
  m[11] = hold[7];
  m[15] = hold[11];

}

void aes_enc_rnd_mix( aes_gf28_t* m ) {
   
   aes_gf28_t s[16];
   memcpy(s, m, 16);
   for(int x = 0; x < 4; x++) {
     m[x*4] = s[x*4 + 3] ^ s[x*4 + 2] ^ xtime(s[x*4]) ^ s[x*4 + 1] ^ xtime(s[x*4 + 1]);
     m[x*4 + 1] = s[x*4 + 3] ^ s[x*4] ^ xtime(s[x*4 +  1]) ^ s[x*4 + 2] ^ xtime(s[x*4 + 2]);
     m[x*4 + 2] = s[x*4] ^ s[x*4 + 1] ^ xtime(s[x*4 + 2]) ^ s[x*4 + 3] ^ xtime(s[x*4 + 3]);
     m[x*4 + 3] = s[x*4 + 1]  ^ s[x*4 + 2] ^ xtime(s[x*4 + 3]) ^ s[x*4] ^ xtime(s[x*4]);
   }

}

void aes_enc_rnd_sub( aes_gf28_t* s ) {
  for (int x = 0; x < 16; x++) {
    s[x] = sbox(s[x]);
  }
}

void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk ) {
  for (int x = 0; x < 16; x++){
    s[x] = s[x] ^ rk[x];
  }
}

void aes_enc_keyexp_step ( aes_gf28_t* r, const aes_gf28_t* rk , aes_gf28_t rc ) {
  r[ 0 ] = rc ^ sbox ( rk[ 13 ] ) ^ rk[ 0 ];
  r[ 1 ] = sbox ( rk[ 14 ] ) ^ rk[ 1 ];
  r[ 2 ] = sbox ( rk[ 15 ] ) ^ rk[ 2 ];
  r[ 3 ] = sbox ( rk[ 12 ] ) ^ rk[ 3 ];
  r[ 4 ] = r[ 0 ] ^ rk[ 4 ];
  r[ 5 ] = r[ 1 ] ^ rk[ 5 ];
  r[ 6 ] = r[ 2 ] ^ rk[ 6 ];
  r[ 7 ] = r[ 3 ] ^ rk[ 7 ];

  r[ 8 ] = r[ 4 ] ^ rk[ 8 ];
  r[ 9 ] = r[ 5 ] ^ rk[ 9 ];
  r[ 10 ] = r[ 6 ] ^ rk[ 10 ];
  r[ 11 ] = r[ 7 ] ^ rk[ 11 ];

  r[ 12 ] = r[ 8 ] ^ rk[ 12 ];
  r[ 13 ] = r[ 9 ] ^ rk[ 13 ];
  r[ 14 ] = r[ 10 ] ^ rk[ 14 ];
  r[ 15 ] = r[ 11 ] ^ rk[ 15 ];
}

aes_gf28_t aes_gf28_add ( aes_gf28_t a, aes_gf28_t b ) {
  return a ^ b;
}

aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b ) {
  aes_gf28_t t = 0;

  for (int i = 7; i >= 0; i--) {
    t = xtime(t);

    if (( b >> i ) & 1) {
      t ^= a;
    }
  }

  return t;
}
aes_gf28_t aes_gf28_inv ( aes_gf28_t a ) {
  aes_gf28_t t_0 = aes_gf28_mul ( a, a ); // a^2
  aes_gf28_t t_1 = aes_gf28_mul ( t_0 , a ); // a^3
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^4
             t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^7
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^8
             t_0 = aes_gf28_mul ( t_1 , t_0 ); // a^15
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^30
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^60
             t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^67
             t_0 = aes_gf28_mul ( t_0 , t_1 ); // a^127
             t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^254
  return t_0;
}

aes_gf28_t sbox( aes_gf28_t a ) {
  a = aes_gf28_inv(a);
  a = ( 0x63 ) ^ // 0 1 1 0 0 0 1 1
    ( a ) ^ // a_7 a_6 a_5 a_4 a_3 a_2 a_1 a_0
    ( a << 1 ) ^ // a_6 a_5 a_4 a_3 a_2 a_1 a_0 0
    ( a << 2 ) ^ // a_5 a_4 a_3 a_2 a_1 a_0 0 0
    ( a << 3 ) ^ // a_4 a_3 a_2 a_1 a_0 0 0 0
    ( a << 4 ) ^ // a_3 a_2 a_1 a_0 0 0 0 0
    ( a >> 7 ) ^ // 0 0 0 0 0 0 0 a_7
    ( a >> 6 ) ^ // 0 0 0 0 0 0 a_7 a_6
    ( a >> 5 ) ^ // 0 0 0 0 0 a_7 a_6 a_5
    ( a >> 4 ) ; // 0 0 0 0 a_7 a_6 a_5 a_4

  return a;
}

aes_gf28_t xtime( aes_gf28_t a ) {
  if ((a & 0x80) == 0x80) {
    return 0x1B ^ ( a << 1 );
  } else {
    return (a << 1);
  }
}
