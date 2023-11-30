#include "../bigint.h"
#include <time.h>

#define MAX_BITLEN 3200

int main(){
    struct bigint 
      N1 
     ,N2 
     ,N3
     ,N4
     ,mod
     ,mod2
     ,R   
     ,R2         
     ;           
  
    bigint_create(&N1,   MAX_BITLEN, 178473 );
    bigint_create(&N2,   MAX_BITLEN, 2 );

    bigint_create(&mod,  MAX_BITLEN, 799777 );  
    
    bigint_create(&R,    MAX_BITLEN, 0   );
    
    /*
    bigint_mod_pow(&N1, &N2, &mod, &R);
    
    output_yel(); printf("\n^^^ Expected: 210343  ^^^\n\n"); output_rst();
    
    bigint_print_info(&R);
    bigint_print_bits(&R);
    */
    
       /* 3000 bits */
    char* bit_number = 
    "0000000000000000000000000000000000000000000000000000000000000000\0"
    ;
    
    
        /* 3000 bits */
    char* mod_string = 
    "000000000000000000000000000000000000000000000000000000000000000000000000\0"
    ;
    
    
    uint32_t len  = strlen(bit_number)
            ,len2 = strlen(mod_string)
            ;                  
    bigint_create_from_string(&N4, 3200, bit_number, len);
    bigint_create_from_string(&mod2, 3200, mod_string, len2);

    clock_t t;
    
    long double times[50];
    struct bigint results[50];
    
    for(uint32_t i = 0; i < 50; ++i){
        bigint_create(&(results[i]), 3200, 0);
    }
    
    for(uint32_t i = 0; i < 1; ++i){
        t = clock();
        
        bigint_add_fast(&N4, &mod2, &(results[i]));   
        
        t = clock() - t;
        times[i] = ((long double)t)/CLOCKS_PER_SEC; //in seconds  
        
    }

    double total_time = 0, avg_time = 0;
    
    printf("[END] --> Times taken:\n");
    
    for(uint32_t i = 0; i < 1; ++i){
        printf("%Lf\n", times[i]);  
        total_time += times[i];  
    }
    
    avg_time = total_time / (double)50;
    
    printf("TOTAL TIME  : %f\n", total_time);
    printf("AVERAGE TIME: %f\n", avg_time);
    
    printf("Result of addition: \n");
    bigint_print_info(&results[0]);
    bigint_print_all_bits(&results[0]);
     
    return 0;

}           
