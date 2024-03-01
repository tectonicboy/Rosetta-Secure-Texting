#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cryptolib.h"

#define RESBITS 12800

/*  PRACTICAL METHOD TO OBTAIN A MONTGOMERY REPRESENTATIVE
 *  
 *	To find X - the Montgomery representative mod M of A, do the following:
 *
 *  Call Montgomery MUL mod M with input one set to (beta^(2*L) mod M), the 
 *	other input set to A itself (in normal PSN notation). The output of this
 *  will in fact be the Montgomery representative of A - X.
 */
 
 
int main(){
	
	struct bigint *G					 = malloc(sizeof(struct bigint))
				, *Q					 = malloc(sizeof(struct bigint))
				, *M					 = malloc(sizeof(struct bigint))
				, *Gmont_PRACTICAL		 = malloc(sizeof(struct bigint))
				, *two					 = malloc(sizeof(struct bigint))
				, *sixtyfour			 = malloc(sizeof(struct bigint))
				, *beta				     = malloc(sizeof(struct bigint))
				, *two_L				 = malloc(sizeof(struct bigint))
				, *beta_to_the_twoL_modM = malloc(sizeof(struct bigint))
 				;
 	/* Will call bigint_create() for them. */	
 	get_M_Q_G(&M, &Q, &G, RESBITS);
 	
	bigint_create(two, 		 RESBITS, 2 );					
	bigint_create(sixtyfour, RESBITS, 64);
	bigint_create(beta,		 RESBITS, 0 );
	bigint_create(two_L,	 RESBITS, 2 * MONT_L );
	
		
		    			
	bigint_create(beta_to_the_twoL_modM, RESBITS, 0);
    bigint_create(Gmont_PRACTICAL, 	     RESBITS, 0);	
    
    /* Now we can perform the actual computations to get (beta^(2*L) mod M). */
    
    /* beta = 2^64 */
    bigint_pow(two, sixtyfour, beta);
    
    printf("\n\n---->> Did 2^64 = beta. <<----\n\n");
    
    printf("two:\n");
    bigint_print_info(two);
    bigint_print_bits(two);
    
    printf("sixtyfour:\n");
    bigint_print_info(sixtyfour);
    bigint_print_bits(sixtyfour);
    
    printf("bigint_pow(two, sixtyfour, beta).\nNow beta:\n");
    bigint_print_info(beta);
    bigint_print_bits(beta);

    
    /* beta^(2*L) mod M */
    bigint_mod_pow(beta, two_L, M, beta_to_the_twoL_modM);
    
    printf("\n\n---->> Did beta^2L mod M = beta_to_the_twoL_modM. <<----\n\n");
    
    printf("two_L:\n");
    bigint_print_info(two_L);
    bigint_print_bits(two_L);
    
    printf("M:\n");
    bigint_print_info(M);
    bigint_print_bits(M);
    
    printf("bigint_mod_pow(beta, two_L, M, beta_to_the_twoL_modM).\n");
    printf("Now beta_to_the_twoL_modM:\n");
    bigint_print_info(beta_to_the_twoL_modM);
    bigint_print_bits(beta_to_the_twoL_modM);
    

    /* Now call MONT MUL. */
    Montgomery_MUL(beta_to_the_twoL_modM, G, M, Gmont_PRACTICAL);
    
    Gmont_PRACTICAL->used_bits = get_used_bits(Gmont_PRACTICAL->bits, 1600);
    
    Gmont_PRACTICAL->free_bits =   Gmont_PRACTICAL->size_bits
    							 - Gmont_PRACTICAL->used_bits;
    							 
    printf("Computed PRACTICAL Montgomery representative of G:\n");
    
    bigint_print_info(Gmont_PRACTICAL);
    bigint_print_bits(Gmont_PRACTICAL);
    
    printf("Saving it to file now.\n");
    
    save_BIGINT_to_DAT("PRACTICAL_Gmont_raw_bytes.dat\0", Gmont_PRACTICAL);
     
 
}
