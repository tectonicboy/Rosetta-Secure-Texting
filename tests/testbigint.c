#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>


#include "../bigint.h"


#define BITS 88


void print_var16_bits(uint16_t X){
          for(uint8_t i = 0; i < 16; ++i){
            if(i < 8){
                if(  ((*((uint8_t*)( &X ))) >> (7-i)) & (uint8_t)1 ){
                    printf("[BYTE 1][%u] : 1  (mem: %p)\n", i, &X);
                }      
                else{
                    printf("[BYTE 1][%u] : 0  (mem: %p)\n", i, &X);
                }   
            }
            else{
                if(  ((* ( ( (uint8_t*)(&X) ) + 1 )) >> (15 - i) ) & (uint8_t)1 ){
                    printf("[BYTE 2][%u] : 1  (mem: %p)\n", i-8, ( ( (uint8_t*)(&X) ) + 1 ));
                }      
                else{
                    printf("[BYTE 2][%u] : 0  (mem: %p)\n", i-8, ( ( (uint8_t*)(&X) ) + 1 ));
                }   
            }
        }

}
int main(){
    /* Incorrectly using the library - ascii bit char buffer needs to nearest 8 bits) */
    
    /*
    uint32_t initializer = 77777777;
   
    uint32_t bitlength = BITS;
    
    struct bigint big1;
    
    bigint_create(&big1, bitlength, initializer);
         
    bigint_print_info(&big1);
         
    char* bitstring = malloc(big1.used_bits);
    
    bigint_get_ascii_bits(&big1, bitstring);
    
    
    printf("\n");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");  
    
    
    bigint_SHIFT_L_by_X(&big1, 3);
    
    bigint_get_ascii_bits(&big1, bitstring); 
    
      
    printf("\n");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");
    
    
    uint32_t init2 = 486464356;
    
    struct bigint big2;
    
    bigint_create(&big2, bitlength, init2);
    
    bigint_print_info(&big2);
    
    char* big2string = malloc(big2.used_bits);
    bigint_get_ascii_bits(&big2, big2string);

    printf("\n");
    for(uint32_t i = 0; i < ceil(big2.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        printf("%c", big2string[i]);
    }
    printf("\n\n");
    
    
    printf(
            "*************************************************\n"
            "*                                               *\n"
            "* TESTING AND, XOR and other bitwise operations *\n"
            "*                                               *\n"
            "*************************************************\n"
            );
    
    printf("\n\n");
    printf("NUMBER 1  : ");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");

    printf("NUMBER 2  : ");
    for(uint32_t i = 0; i < ceil(big2.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", big2string[i]);
    }
    printf("\n");
    
     
    bigint_XOR2(&big1, &big2, &big2);
    
    bigint_get_ascii_bits(&big2, big2string);
    
    printf("num1^num2 : ");
    for(uint32_t i = 0; i < ceil(big2.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", big2string[i]);
    }
    printf("\n");


    printf("\n\n\n");
  
    printf("NUMBER 1  : ");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");

    printf("NUMBER 2  : ");
    for(uint32_t i = 0; i < ceil(big2.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", big2string[i]);
    }
    
    bigint_AND2(&big1, &big2, &big2);
    
    bigint_get_ascii_bits(&big2, big2string);
  
  
    printf("\n");    
    printf("num1&num2 : ");
    for(uint32_t i = 0; i < ceil(big2.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", big2string[i]);
    }
    printf("\n");
    
    printf("\nNOW TESTING SHIFT RIGHT.\n\n");
    
    printf("NUMBER 1      : ");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");
    
    bigint_SHIFT_R_by_X(&big1, 1);
    
    bigint_get_ascii_bits(&big1, bitstring);
    
    printf("NUMBER 1 >> 1 : ");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");
    
    
    
    
    bigint_SHIFT_R_by_X(&big1, 9);
    
    bigint_get_ascii_bits(&big1, bitstring);
    
    printf("NUMBER 1 >> 9 : ");
    for(uint32_t i = 0; i < ceil(big1.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n");
    
    
    printf("\nNOW TESTING COMPARISONS.\n\n");
    
    
    struct bigint big3, big4;
    bigint_create(&big3, 9000, 15); 
    char* bitstring3 = malloc(9000);
    bigint_get_ascii_bits(&big3, bitstring3);
    
    bigint_create(&big4, 9000, 25);
    char* bitstring4 = malloc(9000);
    bigint_get_ascii_bits(&big4, bitstring4);
    
    bigint_print_info(&big3);
    bigint_print_info(&big4);
    
    
    printf("NUMBER 3      : ");
    for(uint32_t i = 0; i < ceil(big3.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring3[i]);
    }
    printf("\n");
    
    
    
    printf("NUMBER 4      : ");
    for(uint32_t i = 0; i < ceil(big4.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring4[i]);
    }
    printf("\n");
    

    uint8_t x1, x2;
    
    x1 = bigint_compare2(&big3, &big4);
    x2 = bigint_compare2(&big4, &big3);
    
    printf("x1 = %u  |  x2 = %u\n\n", x1, x2);
    
    printf("\n\n *** TESTING EQUATING *** \n\n");
    bigint_equate2(&big3, &big4);
    bigint_get_ascii_bits(&big3, bitstring3);
    printf("Result of a3 = a4 : ");
    for(uint32_t i = 0; i < ceil(big3.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring3[i]);
    }
    printf("\n");    
    
    
    struct bigint bigzero;
    bigint_create(&bigzero, 9000, 0); 
    char* bitstringzero = malloc(9000);
    bigint_get_ascii_bits(&bigzero, bitstringzero);
    
    bigint_print_info(&bigzero);
    
    
    
    printf("\n\n *** TESTING ADDITION *** \n\n");
    
    struct bigint big5, big6;
    bigint_create(&big5, 9000, 11389800); 
    char* bitstring5 = malloc(9000);
    bigint_get_ascii_bits(&big5, bitstring5);
       
    bigint_create(&big6, 9000, 12897765);
    char* bitstring6 = malloc(9000);
    bigint_get_ascii_bits(&big6, bitstring6);
    
    struct bigint big7;
    bigint_create(&big7, 9000, 0); 
    char* bitstring7 = malloc(9000);
    
    bigint_print_info(&big5);
    bigint_print_info(&big6);
    
    
    printf("NUMBER 5      : ");
    for(uint32_t i = 0; i < ceil(big5.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring5[i]);
    }
    printf("\n");
    printf("                +\n");  
    printf("NUMBER 6      : ");
    for(uint32_t i = 0; i < ceil(big6.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring6[i]);
    }
    printf("\n");
    
    printf(
        "----------------------------------------------------------------------------\n"
    );    
    

    bigint_add2(&big5, &big6, &big7); 

    
    bigint_get_ascii_bits(&big7, bitstring7);
    
    
    printf("RESULT        : ");
    for(uint32_t i = 0; i < ceil(big7.used_bits / 4) * 8; ++i){
        if( !(i % 8) ){
            printf("  ");
        }
        printf("%c", bitstring7[i]);
    }
    printf("\n");  
    
    bigint_print_info(&big7);  
    
    
    
    */
    
    
    /* Correct ASCII bit printing buffer malloc()ing from here on */
    printf("\n"
        "*******************************************************************\n"
        "*          TESTING OF ZERO PADDING VIA ADDITION TO SELF           *\n"
        "*******************************************************************\n\n"
        );  
        
    uint32_t init_self = 1200039435;
   
    uint32_t bitlength_self = BITS;
    
    struct bigint big_self;
    
    bigint_create(&big_self, bitlength_self, init_self);

 
    struct bigint big_self2;
    bigint_create(&big_self2, bitlength_self, init_self);
  
    struct bigint big_self3;
    bigint_create(&big_self3, bitlength_self, init_self);
    
    
    printf("EEEEEEEEEEEEEEE Before Multiply EEEEEEEEEEEEEEEEEE\n");
    bigint_print_bits(&big_self); 
        bigint_print_info(&big_self);    
    bigint_print_bits(&big_self2); 
        bigint_print_info(&big_self2);
    bigint_print_bits(&big_self3); 
        bigint_print_info(&big_self3);


    bigint_mul2(&big_self, &big_self2, &big_self3);

    printf("EEEEEEEEEEEEEEE After Multiply EEEEEEEEEEEEEEEEEE\n");
    bigint_print_bits(&big_self); 
        bigint_print_info(&big_self);    
    bigint_print_bits(&big_self2); 
        bigint_print_info(&big_self2);
    bigint_print_bits(&big_self3); 
        bigint_print_info(&big_self3);


    return 0;
}



