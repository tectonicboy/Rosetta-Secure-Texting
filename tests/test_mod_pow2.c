#include "../bigint.h"
#include <time.h>

#define MAX_BITLEN 12800

int main(){
    struct bigint 
      N1 
     ,N2 
     ,mod
     ,R         
     ;           
  
    bigint_create(&N1,   MAX_BITLEN, 3001245717);
    bigint_create(&N2,   MAX_BITLEN, 1470024402 );

    bigint_create(&mod,  MAX_BITLEN, 1205444973 );  
    
    bigint_create(&R,    MAX_BITLEN, 0   );

    bigint_mod_pow(&N1, &N2, &mod, &R);
    
    output_yel(); printf("\n^^^ Expected: 818749677 (?) ^^^\n\n"); output_rst();
    
    bigint_print_info(&R);
    bigint_print_bits(&R);
    
    
    free(N1.bits); 
    free(N2.bits); 
    free(mod.bits);
    free(R.bits);   
    
    return 0;
}
