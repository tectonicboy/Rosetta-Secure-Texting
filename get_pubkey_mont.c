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
 * where A is the number want to find the Montgomery representative of, N is
 * the Montgomery modulus (M in our case) and beta and L are constants derived
 * from the Montgomery modulus. X is the generated Montgomery form of A.
 *
 * This is what we use here for now, for public key's Montgomery form too.
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
				, *pub_key
				;
				
	bigint_create(beta,       RESERVED_BITS,  0);
	bigint_create(two,		  RESERVED_BITS,  2);
	bigint_create(sixty_four, RESERVED_BITS, 64);
	bigint_create(div_res,    RESERVED_BITS,  0);
	
	pub_key = get_BIGINT_from_DAT(3072, "testpubkey_raw_bytes.dat\0", 
								  3068, RESERVED_BITS);
								  
	
	bigint_create(M, RESERVED_BITS, 0);
	bigint_create(Q, RESERVED_BITS, 0);
	bigint_create(G, RESERVED_BITS, 0);
	bigint_create(X, RESERVED_BITS, 0);
	bigint_create(L, RESERVED_BITS, MONT_L);
	
	
	
	bigint_pow(two, sixty_four, beta);
	
	
	
	get_M_Q_G(&M, &Q, &G, RESERVED_BITS);
	
	printf("Generator of MONT form of PUB KEY obtained this pubkey:\n");
	bigint_print_info(pub_key);
	bigint_print_bits(pub_key);
	

	struct bigint *beta_to_the_L = malloc(sizeof(struct bigint));
	
	bigint_create(beta_to_the_L, RESERVED_BITS, 0);
	
	bigint_pow(beta, L, beta_to_the_L);
	
	
	
	struct bigint *A_times_betatotheL = malloc(sizeof(struct bigint));
	
	bigint_create(A_times_betatotheL, RESERVED_BITS, 0);
	
	bigint_mul_fast(pub_key, beta_to_the_L, A_times_betatotheL);
	
	
	
	bigint_div2(A_times_betatotheL, M, div_res, X);
	
	printf("COMPUTED MONTGOMERY FORM OF PUBLIC KEY:\n\n");
	
	bigint_print_info(X);
	bigint_print_bits(X);
	
	/* Write G's montgomery form to a .DAT file. */

	char* pub_key_mont_fn = "testpubkeyMONT_raw_bytes.dat\0";

	save_BIGINT_to_DAT(pub_key_mont_fn, X);
	
	return 0; 
}
