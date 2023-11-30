#include "bigint.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#define RM_checks_Q  20
#define RM_checks_M  2
#define factor_siz   40     /* bytes */
#define prime_siz    384    /* bytes */
#define reserved_siz 10000  /* bits  */
#define num_threads  4

struct bigint* Ms;
uint8_t*  Rs;
uint32_t* indices;

struct bigint Q_glob, k_glob, M_glob, one_glob, two_glob, aux1_glob;

uint32_t factor_counter = 0, moduli_counter = 0;

pthread_t tids[num_threads];

pthread_mutex_t lock;

/*
 *  INPUT: The index of RM Result and M of the thread 
 *         that called it and needs to check the next M.
 */
void MainDepot(uint32_t ix){
    pthread_mutex_lock(&lock);
    
    ++moduli_counter;
    printf("Checked %u numbers so far.\n", moduli_counter);
    
    if(Rs[ix]){
        printf("****** FOUND A DIFFIE-HELLMAN MODULUS: *********\n");
      
        printf("M = \n");
        bigint_print_info(&(Ms[ix]));
        bigint_print_all_bits(&Ms[ix]);
        
        printf("Q = \n");
        bigint_print_info(&Q_glob);
        bigint_print_all_bits(&Q_glob);    
        
        printf("Q's checked: %u\nM's checked: %u\n", factor_counter, moduli_counter);
        
        char *M_str = malloc(prime_siz  * 8)
            ,*Q_str = malloc(factor_siz * 8);
        
        memset(M_str, 0x00, prime_siz * 8);
        memset(Q_str, 0x00, factor_siz * 8);
        
       /* Get M to a string in BIG ENDIAN!!! */
       int32_t  a;
       uint32_t j;
       for(a = (prime_siz - 1); a >= 0; --a){
            for(j = 0; j < 8; ++j){
                if( *(((char*)Ms[ix].bits) + a) & ((uint8_t)1 << j) ){
                    M_str[(  (a - (prime_siz - 1)) * 8) + (7 - j)] = '1';    
                }
            }
        }
        
        /* Get Q to a string in BIG ENDIAN!!! */
        for(a = (factor_siz - 1); a >= 0; --a){
            for(j = 0; j < 8; ++j){
                if( *(((char*)Q_glob.bits) + a) & ((uint8_t)1 << j) ){
                    Q_str[(  (a - (factor_siz - 1)) * 8) + (7 - j)] = '1';    
                }
            }
        }
        
        FILE* result;
        
        if( ! (result = fopen("DH_modulus.txt", "w"))){
            printf("[ERR] DH Modulus Generator - can't open DH_modulus.txt for writing. Exiting.\n");
            while(1){continue;}
        }

        if( fwrite((void*)M_str, 1, prime_siz * 8, result) != prime_siz  ){
            printf("[ERR] DH Modulus Generator - Couldn't write M to DH_modulus.txt. Exiting.\n");
            while(1){continue;}
        }
        
        if ( fclose(result) ){
            printf("[ERR] DH Modulus Generator: Failed to close DH_modulus.txt. Exiting.\n");
            while(1){continue;}
        }

        if( ! (result = fopen("DH_mod_factor.txt", "w"))){
            printf("[ERR] DH Modulus Generator - can't open DH_mod_factor.txt for writing. Exiting.\n");
            while(1){continue;}
        }

        if( fwrite((void*)Q_str, 1, factor_siz * 8, result) != factor_siz  ){
            printf("[ERR] DH Modulus Generator - Couldn't write Q to DH_mod_factor.txt. Exiting.\n");
            while(1){continue;}
        }
        
        if ( fclose(result) ){
            printf("[ERR] DH Modulus Generator: Failed to close DH_mod_factor.txt. Exiting.\n");
            while(1){continue;}
        }
        /* Stop all other threads and kill the process. Mission complete! */
        free(Q_str);
        free(M_str);
        printf("FILES should be written to with numbers right now.\n");
        while(1){continue;}
        
    }
    
    else{
        bigint_equate2(&(Ms[ix]), &M_glob);
        bigint_equate2(&aux1_glob, &k_glob);
        bigint_add_fast(&aux1_glob, &two_glob, &k_glob);
        bigint_mul_fast(&Q_glob, &k_glob, &aux1_glob);
        bigint_add_fast(&aux1_glob, &one_glob, &M_glob);
    }
    
    pthread_mutex_unlock(&lock);
    
    return;
}

void* FindNumber(void* arg){

    uint32_t curr_ix = *((uint32_t*)arg);

    while(1){     
        /*printf("**** [thread %u] ENTERING into Rabin Miller. \n", curr_ix);*/
        Rs[curr_ix] = Rabin_Miller(&(Ms[curr_ix]), RM_checks_M);
        /*printf("**** [thread %u] RETURNED from Rabin Miller. About to call MainDepot.\n", curr_ix);*/
        MainDepot(curr_ix);
    }

    return NULL;
}

int main(){

    void* factor = (void*)malloc(factor_siz);
    memset(factor, 0x00, factor_siz);
    
    uint64_t k_siz = (prime_siz - factor_siz); 
    
    void* K_mem = (void*)malloc(k_siz);
    memset(K_mem, 0x00, k_siz);
    
    FILE* urandom;

    if(  !(urandom = fopen("/dev/urandom", "r"))  ){
        printf("[ERR] DH Modulus Generator: Failed to open /dev/urandom for reading. Exiting.\n");
        while(1){continue;}
    }
    
    if( (fread(factor, 1, factor_siz, urandom)) != factor_siz ){
        printf("[ERR] DH Modulus Generator: Failed to read bytes from /dev/urandom. Exiting.\n");
        while(1){continue;}
    } 

    if( (fread(K_mem, 1, k_siz, urandom)) != k_siz ){
        printf("[ERR] DH Modulus Generator: Failed to read bytes from /dev/urandom. Exiting.\n");
        while(1){continue;}
    } 
   
    if ( fclose(urandom) ){
        printf("[ERR] DH Modulus Generator: Failed to close /dev/urandom. Exiting.\n");
        while(1){continue;}
    }
   
    /* Make sure it's at least a factor_siz-bit factor - set the most significant bit to 1. */
    *(((char*)factor) + (factor_siz - 1)) |= ((uint8_t)1 << 7);
    
    /* Make sure it's odd - set the last significant bit to 1. */
    *((char*)factor) |= (uint8_t)1;
    
    /* Make sure K is also at least a factor_siz-bit factor - set the most significant bit to 1. */
    *(((char*)K_mem) + (k_siz - 1)) |= ((uint8_t)1 << 7);
    
    /* Make sure K is even - set the last significant bit to 0. */
    *((char*)K_mem) &= ~((uint8_t)1);

    /* Use the string BigInt constructor. */
    char *factor_str = (char*)malloc( ((factor_siz * 8) + 1)* sizeof(char))
        ,*K_str = (char*)malloc( ((k_siz * 8) + 1) * sizeof(char));
    
    memset(factor_str, 0x00, ((factor_siz * 8) + 1));
    memset(K_str, 0x00, ((k_siz * 8) + 1));
     
    uint32_t i, j; 
     
    /* Get Q to a string. */
    for(i = 0; i < factor_siz; ++i){
        for(j = 0; j < 8; ++j){
            if( *(((char*)factor) + i) & ((uint8_t)1 << j) ){
                factor_str[(i * 8) + (7 - j)] = '1';    
            }
        }
    }
    
    /* Get K to a string. */
   for(i = 0; i < k_siz; ++i){
        for(j = 0; j < 8; ++j){
            if( *(((char*)K_mem) + i) & ((uint8_t)1 << j) ){
                K_str[(i * 8) + (7 - j)] = '1';    
            }
        }
    }

    struct bigint Q, k, M, Q_copy, k_copy, one, two, aux1, aux2;
    
    bigint_create(&Q_glob,    reserved_siz, 0);
    bigint_create(&k_glob,    reserved_siz, 0);
    bigint_create(&M_glob,    reserved_siz, 0);
    bigint_create(&one_glob,  reserved_siz, 0);
    bigint_create(&two_glob,  reserved_siz, 0);
    bigint_create(&aux1_glob, reserved_siz, 0);

    bigint_create_from_string(&Q,      reserved_siz, factor_str, (factor_siz * 8));
    bigint_create_from_string(&Q_copy, reserved_siz, factor_str, (factor_siz * 8));
    
    bigint_create_from_string(&k,      reserved_siz, K_str, (k_siz * 8));
    bigint_create_from_string(&k_copy, reserved_siz, K_str, (k_siz * 8));   
       
    bigint_create(&aux1, reserved_siz, 0);
    bigint_create(&aux2, reserved_siz, 0);    
    
    bigint_create(&one,  reserved_siz, 1);
    bigint_create(&two,  reserved_siz, 2);
    
    bigint_equate2(&one_glob, &one);
    bigint_equate2(&two_glob, &two);
    bigint_equate2(&aux1_glob, &aux1);
         
    while( ! (Rabin_Miller(&Q, RM_checks_Q)) ){
        bigint_equate2(&Q_copy, &Q);
        bigint_add_fast(&Q_copy, &two, &Q);
        printf("Factors checked: %u\n", factor_counter);
        ++factor_counter;
    }

    printf("*************  At this point, we've found a suitable prime factor Q.  *************\n");  

    bigint_mul_fast(&Q, &k, &aux1);
    bigint_add_fast(&aux1, &one, &aux2);
    
    bigint_equate2(&Q_glob, &Q);
    bigint_equate2(&k_glob, &k);
    bigint_equate2(&M_glob, &aux2);
    
    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("[ERR] RM Modulus Generator - failed to initialize mutex lock. Exiting.\n\n");
        while(1){continue;}
    }
    
    Ms = malloc(num_threads * sizeof(struct bigint));
    Rs = malloc(num_threads * sizeof(uint8_t));
    indices = malloc(num_threads * sizeof(uint32_t));
    
    i = 0;
    while(i < num_threads){
    
        bigint_create(&Ms[i], reserved_siz, 0);
    
        indices[i] = i;

        bigint_equate2(&(Ms[i]), &M_glob);
        
        bigint_equate2(&aux1_glob, &k_glob);
        bigint_add_fast(&aux1_glob, &two_glob, &k_glob);
        bigint_mul_fast(&Q_glob, &k_glob, &aux1_glob);
        bigint_add_fast(&aux1_glob, &one_glob, &M_glob);
        
        ++i;
    }
  
    int error;
    
    i = 0;
    while (i < num_threads) {

        error = pthread_create(
                               &(tids[i]),
                               NULL,
                               &FindNumber, 
                               (void*)(indices + i)
                               );
        if (error != 0){
            printf("[ERR] RM Modulus Generator - couldn't start thread. Exiting.\n");
            while(1){continue;}
        }
        
        ++i;
    }
 
    pthread_join(tids[0], NULL);

    free(factor);
    free(factor_str);
    free(K_mem);
    free(K_str);
    free(Ms);
    free(Rs);
    free(indices);
}
