#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bigint.h"

struct bigint* get_BIGINT_from_DAT(uint32_t bits, char* fn, uint32_t used_bits
                                  ,uint32_t reserve_bits){


    if(reserve_bits < used_bits){
        printf("ERROR: Used bits in .dat file > desired reserved bits.\n");
    }
    
    FILE* dat_file = fopen(fn, "r");
    
    uint32_t bytes = (uint32_t)(bits/8);
    
    char* bigint_buf = malloc(bytes);
    
    fread(bigint_buf, 1, bytes, dat_file);
    
    struct bigint* big_n_ptr = malloc(sizeof(struct bigint));
    
    bigint_create(big_n_ptr, reserve_bits, 0);
    
    memcpy(big_n_ptr->bits, bigint_buf, bytes);
    
    big_n_ptr->used_bits = used_bits;
    big_n_ptr->free_bits = bits - used_bits;
    
    return big_n_ptr;

}

/* G = ( 2^((M-1)/Q) ) mod M */
struct bigint* get_DH_G(struct bigint* M, struct bigint* Q){
    
    struct bigint M_minus_one, power, zero, one, two, div_rem, *G;
    
    G = malloc(sizeof(struct bigint));
    
    printf("IN FUNCTION to get G: M->size_bits = %u\n", M->size_bits);
    
    bigint_create(&M_minus_one, M->size_bits, 0);
    bigint_create(&power,       M->size_bits, 0);
    bigint_create(&one,         M->size_bits, 1);
    bigint_create(&two,         M->size_bits, 2);   
    bigint_create(G,            M->size_bits, 0);     
    bigint_create(&div_rem,     M->size_bits, 0); 
    bigint_create(&zero,        M->size_bits, 0);
    
    printf("IN FUNCTION to get G: one.size_bits = %u\n", one.size_bits); 
             
    bigint_sub2(M, &one, &M_minus_one);

    
    bigint_div2(&M_minus_one, Q, &power,  &div_rem);
    
    if( bigint_compare2(&div_rem, &zero) != 2 ){
        printf("ERROR: (M-1) / Q   gave a remainder?!?!!\n\n");
        exit(1);
    }
    
    bigint_mod_pow(&two, &power, M, G);
    
    printf("---->>> COMPUTED G = 2^(M-1/Q) mod M\n\n");
    
    bigint_print_info(G);
    bigint_print_bits(G);
    bigint_print_all_bits(G);
             
    return G;    
}

int main(){

    uint32_t bits_Q = 320, used_bits_Q = 320, res_bits_Q = 6400;
    
    char* filename_Q_dat = "Q_raw_bytes.dat";

    struct bigint* result_ptr_Q;
    
    result_ptr_Q = get_BIGINT_from_DAT(bits_Q, filename_Q_dat, used_bits_Q, res_bits_Q);
    
    printf("OBTAINED A BIGINT OBJECT FROM .DAT FILE for Q!!\n");
    
    printf("Now printing the Q BigInt's info:\n\n");
    
    bigint_print_info(result_ptr_Q);
    
    printf("\nNow printing the Q BigInt's bits:\n\n");
    
    bigint_print_bits(result_ptr_Q);
    
    printf("\nNow printing the Q BigInt's ALL bits:\n\n");
    
    bigint_print_all_bits(result_ptr_Q);
    

    
    uint32_t bits_M = 3072, used_bits_M = 3071, res_bits_M = 6400;
    
    char* filename_M_dat = "M_raw_bytes.dat";

    struct bigint* result_ptr_M;
    
    result_ptr_M = get_BIGINT_from_DAT(bits_M, filename_M_dat, used_bits_M, res_bits_M);
    
    printf("OBTAINED A BIGINT OBJECT FROM .DAT FILE for M!!\n");
    
    printf("Now printing the M BigInt's info:\n\n");
    
    bigint_print_info(result_ptr_M);
    
    printf("\nNow printing the M BigInt's bits:\n\n");
    
    bigint_print_bits(result_ptr_M);
    
    printf("\nNow printing the M BigInt's ALL bits:\n\n");
    
    bigint_print_all_bits(result_ptr_M);    
    
    
    printf("Now we can generate G.\n");
    
    
    
    
    
    struct bigint* G;
    
    G = get_DH_G(result_ptr_M, result_ptr_Q);
    
    printf("Retrieved result from function - G has been generated:\n\n");
    
    bigint_print_info(G);
    bigint_print_bits(G);
    bigint_print_all_bits(G);
    
    return 0;

}





















