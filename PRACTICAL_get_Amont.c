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
				, *Amont_PRACTICAL		 = malloc(sizeof(struct bigint))
				, *two					 = malloc(sizeof(struct bigint))
				, *sixtyfour			 = malloc(sizeof(struct bigint))
				, *L					 = malloc(sizeof(struct bigint))
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
    bigint_create(Amont_PRACTICAL, 	     RESBITS, 0);	
    
    /* Now we can perform the actual computations to get (beta^(2*L) mod M). */
    
    /* beta = 2^64 */
    bigint_pow(two, sixtyfour, beta);
    
    /* beta^(2*L) mod M */
    bigint_mod_pow(beta, two_L, M, beta_to_the_twoL_modM);
    printf("GET_Amont: beta_to_the_twoL_modM before Mont_MUL call:\n");
    bigint_print_info(beta_to_the_twoL_modM);
    bigint_print_bits(beta_to_the_twoL_modM);
    /* Now call MONT MUL. */
    
    /* Here, instead of feeding G, we feed the public key A. */
    struct bigint *PRACTICAL_PUBKEY =
    			 get_BIGINT_from_DAT( 3072
									 ,"PRACTICAL_testpubkey_raw_bytes.dat\0"
									 ,3070
									 ,RESBITS
									);

	printf("BIG-ENDIAN PRACTICAL_PUBKEY before Mont_MUL call:\n\n");
    printf("Printing info and BIG-ENDIAN bytes of PRACTICAL PUBKEY:\n");
    bigint_print_info(PRACTICAL_PUBKEY);
    bigint_print_bits_bigend(PRACTICAL_PUBKEY);
    
    Montgomery_MUL(beta_to_the_twoL_modM, PRACTICAL_PUBKEY, M, Amont_PRACTICAL);
    
    Amont_PRACTICAL->used_bits = get_used_bits(Amont_PRACTICAL->bits, 1600);
    
    Amont_PRACTICAL->free_bits =   Amont_PRACTICAL->size_bits
    							 - Amont_PRACTICAL->used_bits;
    							 
    printf("Computed PRACTICAL Montgomery representative of test pubkey A:\n");
    
    bigint_print_info(Amont_PRACTICAL);
    bigint_print_bits(Amont_PRACTICAL);
    
    printf("Saving it to file now.\n");
    
    save_BIGINT_to_DAT("PRACTICAL_Amont_raw_bytes.dat\0", Amont_PRACTICAL);
    
    printf("Printing BIG-ENDIAN bytes of PRACTICAL Amont:\n");
    bigint_print_bits_bigend(Amont_PRACTICAL);
    
    return 0;
     
 
}
