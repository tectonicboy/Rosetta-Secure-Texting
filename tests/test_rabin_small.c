#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>

#include <time.h>

#include "../bigint.h"

int main(){
   
    clock_t t;
    double time;
    struct bigint big_prime;
    uint8_t RM_res;

    char* prime_string = 
   "0000000100000001000000000000000000000000000000000000000000000000\0"
    ;
    
    uint32_t len = strlen(prime_string);
    printf("LEN = %u\n", len);
    bigint_create_from_string(&big_prime, 96, prime_string, len);
    
    uint32_t passes = 2;

 
    printf("Rabin-Miller will test this 3000-bit number (big-endian format):\n");
    
    bigint_print_bits_bigend(&big_prime);

    t = clock();
    
    RM_res = Rabin_Miller(&big_prime, passes);  
      
    t = clock() - t;
    
    time = ((double)t)/CLOCKS_PER_SEC; //in seconds  

 

    output_red(); 
    printf("\n[END] ---> "); 
    if(RM_res){ printf("PRIME\n\n"); }
    else{ printf("COMPOSITE\n\n"); }
    output_rst();
    printf("Time taken to check with %u passes: %f seconds\n", passes, time);
      
           
    return 0;
        
}           
