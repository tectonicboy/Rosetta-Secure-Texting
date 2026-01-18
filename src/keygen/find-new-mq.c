#include "../lib/bigint.h"
#include <pthread.h>

/******************************************************************************/

#define PRINT_RED(string)   "\x1b[31m"  string "\x1b[0m"
#define PRINT_BLUE(string)  "\x1b[34m" string "\x1b[0m"
#define SET_PRINT_BG_CYAN   printf("\x1b[46m");
#define SET_PRINT_BG_BLACK  printf("\x1b[40m");
#define MAXIMUM_BITS        12000
#define SIZE_Q_BITS         320
#define SIZE_Q_BYTES        40
#define SIZE_M_BITS         3072
#define SIZE_M_BYTES        384
#define RABIN_MILLER_PASSES 64
#define NUM_THREADS         24

//const uint64_t NUM_THREADS = (uint64_t)sysconf(_SC_NPROCESSORS_ONLN);

uint64_t is_dh_modulus_found[NUM_THREADS];

void* thread_function_checker(void* thread_input_buffer){
									 
    uint64_t alert_ix;                                                       
    bigint   testing_M;                                                      
									 
    memcpy(&testing_M, thread_input_buffer, sizeof(bigint));               
    memcpy(&alert_ix, ((u8*)thread_input_buffer) + sizeof(bigint), sizeof(u64));
    
    uint8_t is_prime = rabin_miller(&testing_M, RABIN_MILLER_PASSES);        
									 
    if(is_prime){
        is_dh_modulus_found[alert_ix] = 1;                                   
    }                                                                        
									 
    return NULL;       
}

int main(void){

    void*     thread_func_inputs[NUM_THREADS];
    pthread_t thread_ids[NUM_THREADS];

    bigint M;
    bigint Q;
    bigint one;
    bigint two;
    bigint tmp;
    bigint aux;
    bigint test_Ms[NUM_THREADS];

    FILE* rand_fd = NULL;

    size_t bytes_read;
    size_t counter = 0;

    uint8_t keep_searching = 1;
    uint8_t is_prime = 0;

    bigint_create_from_u32(&M,   MAXIMUM_BITS, 0);
    bigint_create_from_u32(&Q,   MAXIMUM_BITS, 0);
    bigint_create_from_u32(&one, MAXIMUM_BITS, 1);
    bigint_create_from_u32(&two, MAXIMUM_BITS, 2);
    bigint_create_from_u32(&tmp, MAXIMUM_BITS, 0);
    bigint_create_from_u32(&aux, MAXIMUM_BITS, 0);

    for(uint64_t i = 0; i < NUM_THREADS; ++i){
        bigint_create_from_u32(&(test_Ms[i]), MAXIMUM_BITS, 0);
        thread_func_inputs[i] = calloc( 1, sizeof(uint64_t) + sizeof(bigint) );
        is_dh_modulus_found[i] = 0;
    }

    /* Generate random 320-bit Q. Set last and 1st bit to 1. */
    /* This ensures it's really 320-bit and it's odd.        */

    
    rand_fd = fopen("/dev/urandom", "r");
    if(rand_fd == NULL){
        printf("[ERR]  Q  fopen() failed.\n");
        goto label_cleanup;
    }
    
    bytes_read = fread(Q.bits, 1, SIZE_Q_BYTES, rand_fd);
    
    if(bytes_read != SIZE_Q_BYTES){
        printf("[ERR]  Q  fread() failed.\n");
        goto label_cleanup;
    }    

    Q.bits[SIZE_Q_BYTES - 1] |= (1 << 7);
    Q.bits[0] |= (1 << 0);

    Q.used_bits = get_used_bits(Q.bits, SIZE_Q_BYTES);

    while(is_prime == 0){
        printf("Finding 320-bit prime  Q  --  numbers checked: %lu\n", counter);
        
        is_prime = rabin_miller(&Q, RABIN_MILLER_PASSES);
        
        ++counter;
        
        if(is_prime == 1){
            printf("\n---> Q prime found!!\n\n");
            bigint_print_info(&Q);
            bigint_print_bits(&Q);
            break;
        }
        
        bigint_equate2(&tmp, &Q);                                            
        bigint_add_fast(&tmp, &two, &Q);
    }

    /* For finding M. */
    counter  = 0;

    /**************************************************************************/

    printf("\n\n============ STARTING TO FIND 3072-BIT  M  ==============\n\n");
    
label_keep_searching:

    /* Prepare test M's for each thread to check. 
     * Instead of doing AUX += 2 for each one, generate new ~2700-bit UAX.
     * This apparently ensures we make use of the Riemann hypothesis for prime
     * sparsity, saying about one in 3070 are prime around 2^3070. And
     * incrementing does not allow us to do that because arithmetic progression
     * created by it makes it not a random distribution of searched numbers?
     */

    for(uint64_t i = 0; i < NUM_THREADS; ++i){  
        
        memset(aux.bits, 0x00, SIZE_M_BYTES - SIZE_Q_BYTES);                   
        bytes_read = fread(aux.bits, 1, SIZE_M_BYTES - SIZE_Q_BYTES, rand_fd); 
                                                                           
        if(bytes_read != SIZE_M_BYTES - SIZE_Q_BYTES){                         
            printf("[ERR]  AUX  fread() failed.\n");                           
            goto label_cleanup;                                                
        }                                                                      
                                                                           
        aux.bits[SIZE_M_BYTES - SIZE_Q_BYTES - 1] |= (1 << 7);                 
        aux.bits[0] &= ~(1 << 0);                                              
        aux.used_bits = get_used_bits(aux.bits, SIZE_M_BYTES - SIZE_Q_BYTES);  
        
        bigint_mul_fast(&Q, &aux, &(test_Ms[i]));
        bigint_equate2(&tmp, &(test_Ms[i]));
        bigint_add_fast(&tmp, &one, &(test_Ms[i]));
    }

    /* Prepare each thread's input buffer. */


    /* is_dh_modulus_found[i] (so, i) AND POINTER TO testM[i] !!! 
     * Start each thread. Wait for all threads to finish.
     * If none of the global prime found indicators is activated, rince repeat.
     */
    
    printf("\n");
    
    for(uint64_t i = 0; i < NUM_THREADS; ++i){
        memcpy(thread_func_inputs[i], &(test_Ms[i]), sizeof(bigint));
        memcpy(((u8*)thread_func_inputs[i]) + sizeof(bigint), &i, sizeof(u64));

        pthread_create( &(thread_ids[i])
                       ,NULL
                       ,thread_function_checker
                       ,thread_func_inputs[i]
                      ); 
    }

    for(uint64_t i = 0; i < NUM_THREADS; ++i){
        pthread_join(thread_ids[i], NULL);
    }

    counter += NUM_THREADS;

    time_t t = time(NULL);                                                   
    struct tm tm = *localtime(&t);

    SET_PRINT_BG_CYAN
    printf(PRINT_RED("\n[%d-%02d-%02d %02d:%02d:%02d] ")
           ,tm.tm_year + 1900,tm.tm_mon + 1, tm.tm_mday
           ,tm.tm_hour, tm.tm_min, tm.tm_sec 
          );
    SET_PRINT_BG_BLACK

    printf("All %u threads finished.\nDiscoveries: [", NUM_THREADS);

    for(uint64_t i = 0; i < NUM_THREADS; ++i){
        printf(" %lu ", is_dh_modulus_found[i]);
        if(is_dh_modulus_found[i] == 1){

            printf("\n\n ===========>>>   Found M  <<<=========\n\n");
            printf("It was found by thread [%lu]:\n", i);
            bigint_print_info(&(test_Ms[i]));
            bigint_print_bits(&(test_Ms[i]));

            keep_searching = 0;
        }
    }
    printf("]\n");  

    if(keep_searching){
        printf("\n3072-bit primes checked: %lu  --  ", counter);
        printf("The search continues.\n\n");
        goto label_keep_searching;
    }

label_cleanup:
    
    if(rand_fd != NULL)
        fclose(rand_fd);

    bigint_cleanup(&M);
    bigint_cleanup(&Q);
    bigint_cleanup(&two);
    bigint_cleanup(&aux); 
    bigint_cleanup(&tmp);
    bigint_cleanup(&one);

    for(uint64_t i = 0; i < NUM_THREADS; ++i){
        free(thread_func_inputs[i]);
        bigint_cleanup(&(test_Ms[i]));
    }

    return 0;
}

