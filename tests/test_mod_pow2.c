#include "../bigint.h"
#include <time.h>

#define MAX_BITLEN 8000

int main(){
    struct bigint 
      N1 
     ,N2 
     ,mod
     ,R         
     ;           
  
    bigint_create(&N1,   MAX_BITLEN, 2);
    bigint_create(&N2,   MAX_BITLEN, 39003 );

    bigint_create(&mod,  MAX_BITLEN, 78007 );  
    
    bigint_create(&R,    MAX_BITLEN, 0   );

    bigint_mod_pow(&N1, &N2, &mod, &R);
    
    output_yel(); printf("\n^^^ Expected: 1  ^^^\n\n"); output_rst();
    
    bigint_print_info(&R);
    bigint_print_bits(&R);
    
    
    free(N1.bits); 
    free(N2.bits); 
    free(mod.bits);
    free(R.bits);   
    
    return 0;
}
