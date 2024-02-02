#include <stdint.h>
#include <stdio.h>
#include "bigint.h"

/* We use this specific algorithm to compute mu for Montgomery.   		*/
/* invmod(beta - lowest_64bit_limb_of_DH_modulus_M) = mu for MMM. 		*/
/* beta being the radix for MMM, in our case 2^64 (2^limb_size_in_bits)	*/
uint64_t invmod(uint64_t a){
	uint32_t x = (((a + 2u)&4u)<<1)+a;
	x    =  (2u-1u*a*x)*x;
	x    =  (2u-1u*a*x)*x;
	x    =  (2u-1u*a*x)*x;
	return ((2u-1u*a*x)*x);
} 

int main(){

	struct bigint *beta       = malloc(sizeof(struct bigint))
				, *lowest_M   = malloc(sizeof(struct bigint))
				, *two        = malloc(sizeof(struct bigint))
				, *sixty_four = malloc(sizeof(struct bigint))
				, *a	      = malloc(sizeof(struct bigint))
				;
				
	bigint_create(beta,       320,  0);
	bigint_create(lowest_M,	  320,  0);
	bigint_create(two,		  320,  2);
	bigint_create(sixty_four, 320, 64);
	bigint_create(a,		  320,  0);
	
	bigint_pow(two, sixty_four, beta);

	*((uint64_t*)(lowest_M->bits)) = (uint64_t)15205348319790726673ULL;
	
	lowest_M->used_bits = 61;
	lowest_M->free_bits = 320 - 61;
	
	uint64_t lowest_M_justincase = 
			 0b1101001100000100001111111011110001000111001101010111111000010001;
			   
	if(lowest_M_justincase ==  *((uint64_t*)(lowest_M->bits)) ){
		printf("OK for sure it's right, they're equal.\n");
	}
	
	bigint_sub2(beta, lowest_M, a);
	
	printf("The input to invmod, a, is ready! a:\n");
	
	bigint_print_info(a);
	bigint_print_bits(a);
	bigint_print_all_bits(a);
	
	uint64_t MU;
	
	MU = invmod(*((uint64_t*)(a->bits)));
	
	printf("We have our MU for Montgomery!!\nMU = %lu\n\n", MU);
	
	return 0;
}
