#include "../bigint.h"

#define MAX_BITLEN 16000 

    
int main(){
/*
    struct bigint 
      N1
     ,N1_from_string
     ,N2_from_string 
     ,N2          
     ,R0
     ,rem0 
     ;           
                
    bigint_create(&N1,   MAX_BITLEN, 3441200307);
    bigint_create(&N2,   MAX_BITLEN, 600431 );

    bigint_create(&R0,   MAX_BITLEN, 0);
    bigint_create(&rem0, MAX_BITLEN, 0);
    
    bigint_print_info(&N1);
    bigint_print_bits(&N1);
    printf("\nDIVIDED BY\n");
    bigint_print_info(&N2);
    bigint_print_bits(&N2);
    
    
    bigint_div2(&N1, &N2, &R0, &rem0);
    
    
    printf("\nResult of DIV:\n");
    bigint_print_info(&R0);
    bigint_print_bits(&R0);
    
    printf("Remainder of DIV:\n");
    bigint_print_info(&rem0);
    bigint_print_bits(&rem0);
    
   // output_yel(); printf("\n^^^ Expected: res=2 and rem=4 ^^^\n\n"); output_rst();
     
     
    char *N1_str = "10110011100011000001110011001101\0",
         *N2_str = "011011110010100100001001\0";
     
    uint32_t N1_len = strlen(N1_str),
             N2_len = strlen(N2_str); 
          
    bigint_create_from_string(&N1_from_string, MAX_BITLEN, N1_str, N1_len);
    bigint_create_from_string(&N2_from_string, MAX_BITLEN, N2_str, N2_len);
    
    printf("NOW DIVIDING STRINGIFIED BIGINTS:\n");
    
    bigint_print_info(&N1_from_string);
    bigint_print_bits(&N1_from_string);
    printf("\nDIVIDED BY\n");
    bigint_print_info(&N2_from_string);
    bigint_print_bits(&N2_from_string);
    
    bigint_div2(&N1_from_string, &N2_from_string, &R0, &rem0);
    
    printf("Result after dividing the same bigints but created from strings:\n");
    printf("\nResult of string DIV:\n");
    bigint_print_info(&R0);
    bigint_print_bits(&R0);
    
    printf("Remainder of string DIV:\n");
    bigint_print_info(&rem0);
    bigint_print_bits(&rem0);
    
     */     
    struct bigint x1, x2, x_res, x_rem;
    
    bigint_create(&x1, 3000, 78006);
    bigint_create(&x2, 3000, 2);
    bigint_create(&x_res, 3000, 0);
    bigint_create(&x_rem, 3000, 0);
    
    bigint_div2(&x1, &x2, &x_res, &x_rem);
          
    printf("After dividing 78006 by 2, we get:\n\nResult = \n");
    bigint_print_info(&x_res);
    bigint_print_bits(&x_res);
    printf("Remainder = \n");
    bigint_print_info(&x_rem);
    bigint_print_bits(&x_rem);         
          
          
          
    return 0;
          
          
          
          
             
}  
