#include "../bigint.h"

#define BITLEN 7008

    
int main(){

    struct bigint 
      N1    
     ,N2        
     ,R0       
     ,two     
     ;           
                
    bigint_create(&N1,   BITLEN, 2048 );
    bigint_create(&N2,   BITLEN, 2048 );
    bigint_create(&two,  BITLEN, 2);
    bigint_create(&R0,   BITLEN, 0);

    

  
    bigint_add_fast(&N1, &N2, &R0);
    
    printf("Result of adder test:\n");

    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);
         
}           
