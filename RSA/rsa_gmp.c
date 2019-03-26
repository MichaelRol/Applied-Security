
#include "gmp.h"
#include <math.h>

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda);
void l2r_lexp( mpz_t r, mpz_t x, mpz_t y, mpz_t N);
void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N);
void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N);

int main( int argc, char* argv[] ) {
    mpz_t N, e, d;
    mpz_init( e );
    mpz_init( d );
    mpz_init( N );
    rsa_keygen(N, e, d, 10);
    
    return 0;
}

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda){
    gmp_randstate_t rstate;
    gmp_randinit_mt(rstate);
    mpz_t p;
    mpz_t q;
    mpz_init( p );
    mpz_init( q );
    mpz_urandomb(p, rstate, pow(2, lambda));
    mpz_urandomb(q, rstate, pow(2, lambda));
    mpz_mul(N, p, q);
    gmp_printf( "%Zd\n", N );   


}

void l2r_lexp( mpz_t r, mpz_t x, mpz_t y, mpz_t N){


}

void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N){


}

void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N){


}