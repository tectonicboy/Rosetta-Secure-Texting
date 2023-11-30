#include "../bigint.h"

#define MAX_BITLEN 16000 

    
int main(){

    struct bigint 
      N1   
     ,N2          
     ,R0              
     ;           
                
    bigint_create(&N1,   MAX_BITLEN, 2000000000 );
    bigint_create(&N2,   MAX_BITLEN, 0 );

    bigint_create(&R0,   MAX_BITLEN, 0);
    
    bigint_print_bits(&N1);
    printf("-\n");
    bigint_print_bits(&N2);
    
    
    bigint_sub2(&N1, &N2, &R0);
    
    
    printf("Result of subtraction:\n");
    bigint_print_bits(&R0);
    bigint_print_info(&R0);
    
    output_yel(); printf("\n^^^ Expected: 2000000000 ^^^\n\n"); output_rst();
         
}  
