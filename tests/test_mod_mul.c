        #include "../bigint.h"

#define MAX_BITLEN 8000

int main(){
    struct bigint 
      N1 
     ,N2 
     ,N3 
     ,N4 
     ,N5
     ,N6
     ,N7
     ,N8
     ,mod
     ,R            
     ;           
  
    bigint_create(&N1,   MAX_BITLEN, 48414 );
    bigint_create(&N2,   MAX_BITLEN, 722 );
    bigint_create(&N3,   MAX_BITLEN, 10661 );
    bigint_create(&N4,   MAX_BITLEN, 71380);
    bigint_create(&N5,   MAX_BITLEN, 65536  );
    bigint_create(&N6,   MAX_BITLEN, 256);
    bigint_create(&N7,   MAX_BITLEN, 4 );   
    bigint_create(&N8,   MAX_BITLEN, 2 );

    bigint_create(&mod,  MAX_BITLEN, 78007 );  
    
    bigint_create(&R,    MAX_BITLEN, 0   );

    struct bigint** bigint_arr = malloc(8 * sizeof(struct bigint*));

    bigint_arr[0] = &N1;
    bigint_arr[1] = &N2;
    bigint_arr[2] = &N3;
    bigint_arr[3] = &N4;
    bigint_arr[4] = &N5;
    bigint_arr[5] = &N6;
    bigint_arr[6] = &N7;
    bigint_arr[7] = &N8;

    uint32_t how_many = 8;
  
    bigint_mod_mul(bigint_arr, &mod, how_many, &R);
    
    output_yel(); printf("\n^^^ Expected: 1  ^^^\n\n"); output_rst();
    
    bigint_print_info(&R);
    bigint_print_bits(&R);
    
    free(N1.bits); 
    free(N2.bits); 
    free(N3.bits); 
    free(N4.bits); 
    free(N5.bits); 
    free(N6.bits); 
    free(N7.bits); 
    free(N8.bits);
    free(mod.bits);
    free(R.bits);        
    
    return 0;

} 
