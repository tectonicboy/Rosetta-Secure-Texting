#include "../bigint.h"

#define MAX_BITLEN 3000

    
int main(){

    struct bigint 
      N1   
     ,N2          
     ,R0              
     ;           
                
    bigint_create(&N1,   MAX_BITLEN, 0 );
    bigint_create(&N2,   MAX_BITLEN, 1 );

    bigint_create(&R0,   MAX_BITLEN, 0);
    
                printf("[TEST ADD] - The ADDITION performed is:\n");
                bigint_print_info(&N1);
                bigint_print_all_bits(&N1);  
                printf("\nPLUS\n");
                bigint_print_info(&N2);
                bigint_print_all_bits(&N2);  

    
    
    bigint_add2(&N1, &N2, &R0);
    
    
    printf("After adding one to N1, now RES = \n");  
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);  
    
    output_yel(); printf("\n^^^ Expected: 1 ^^^\n\n"); output_rst();
         
}  
