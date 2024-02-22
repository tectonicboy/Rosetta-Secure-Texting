#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cryptolib.h"

#define RESERVED_BITS 12800

/* Strange observation: Can't use the "practical method" that uses 
 * beta^(2*L) mod p, to precompute G's Montgomery form because p
 * changes with each message and thus each generated signature?...
 *
 * The other method was: X = (A * (beta^L)) mod N)
 *
 *
 */

int main(){
	struct bigint *beta       = malloc(sizeof(struct bigint))
				, *two        = malloc(sizeof(struct bigint))
				, *sixty_four = malloc(sizeof(struct bigint))
				, *div_res    = malloc(sizeof(struct bigint))
				, *M		  = malloc(sizeof(struct bigint))	
				, *Q		  = malloc(sizeof(struct bigint))
				, *G	      = malloc(sizeof(struct bigint))
				, *X		  = malloc(sizeof(struct bigint))
				, *L		  = malloc(sizeof(struct bigint))
				;
				
	bigint_create(beta,       RESERVED_BITS,  0);
	bigint_create(two,		  RESERVED_BITS,  2);
	bigint_create(sixty_four, RESERVED_BITS, 64);
	bigint_create(div_res	, RESERVED_BITS,  0);

	bigint_create(X, RESERVED_BITS, 0);
	bigint_create(L, RESERVED_BITS, MONT_L);
	
	bigint_pow(two, sixty_four, beta);
	
	get_M_Q_G(&M, &Q, &G, RESERVED_BITS);

	struct bigint *beta_to_the_L = malloc(sizeof(struct bigint));
	
	bigint_create(beta_to_the_L, RESERVED_BITS, 0);
	
	bigint_pow(beta, L, beta_to_the_L);
	
	struct bigint *A_times_betatotheL = malloc(sizeof(struct bigint));
	
	bigint_create(A_times_betatotheL, RESERVED_BITS, 0);
	
	bigint_mul_fast(G, beta_to_the_L, A_times_betatotheL);
	
	bigint_div2(A_times_betatotheL, M, div_res, X);
	
	printf("COMPUTED MONTGOMERY FORM OF G:\n\n");
	
	bigint_print_info(X);
	bigint_print_bits(X);
	bigint_print_all_bits(X);
	
	/* Write G's montgomery form to a .DAT file. */

	FILE* Gmont_dat = fopen("Gmont_raw_bytes.dat", "w");
	
	uint32_t X_used_bytes = X->used_bits;
	
	while(X_used_bytes % 8 != 0){
		++X_used_bytes;
	}
	
	X_used_bytes /= 8;
	
	printf("X_used_bytes = %u ... Writing bytes to file.\n", X_used_bytes);
	
	fwrite(X->bits, 1, X_used_bytes, Gmont_dat);
	
	fclose(Gmont_dat);
	
	return 0; 
}
