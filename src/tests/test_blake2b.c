#include "cryptolib.h"

#define RESBITS 12800

void uint32_print_bits(uint32_t n){
    printf("\n****** Printing bits of uint32 N = %u ******\n", n);
    for(uint8_t i = 0; i < 32; ++i){
        if(n & ( 1 << (31-i) )){
            printf("1");    
        }
        else{
            printf("0");
        }
        if( i==7 || i==15 || i==23 || i==31 ){
            printf(" ");
        }
    }
    printf("\n\n");
}

int main(){

    /********** NOW TESTING BLAKE2B ***************/


    /* Prepare message to be processed by BLAKE2b. */
    
    char *b2b_raw_msg = "abc\0",
         *b2b_out_buf = malloc(65 * sizeof(char));
         
    memset(b2b_out_buf, 0x00, 65*sizeof(char));
    
    
    uint64_t b2b_ll = strlen(b2b_raw_msg)
            ,b2b_kk = 0
            ,b2b_nn = 64
            ;
      
      
    printf("**** PASSING ARGUMENTS TO BLAKE2B:\n");
    printf("ll = %lu\n", b2b_ll);
    BLAKE2B_INIT(b2b_raw_msg
                ,b2b_ll
                ,b2b_kk
                ,b2b_nn
                ,b2b_out_buf
                );
                
    printf("BLAKE2b produced 64-byte hash:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)b2b_out_buf[i]);
    }
    printf("\n\n");
    
    free(b2b_out_buf);
    
    
    
    return 0;
    
}
