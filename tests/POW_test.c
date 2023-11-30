#include "../bigint.h"

#define MAX_BITLEN 1000000

    
int main(){

    struct bigint 
      N1    /* 2 */
     ,N2    /* 2 */        
     ,R0    /* 65536^2 */       
     ,two   /* 2 */     
     ;           
                
    bigint_create(&N1,   7008, 65536 );
    bigint_create(&N2,   7008, 2 );
    bigint_create(&two,  7008, 2);
    bigint_create(&R0,   7008, 0);

    

  
    bigint_pow(&N1, &N2, &R0);
    
    printf("Result of 65536^2: (should be 2^32, aka 1 with 4*8 zeroes behind it.)\n");

    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);
         
}           
