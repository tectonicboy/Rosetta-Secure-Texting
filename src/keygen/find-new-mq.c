#include "../lib/bigint.h"
#include <pthread.h>

#define MAXIMUM_BITS        12000
#define SIZE_Q_BITS         320
#define SIZE_Q_BYTES        40
#define SIZE_M_BITS         3072
#define SIZE_M_BYTES        384
#define RABIN_MILLER_PASSES 64
#define NUM_THREADS         24

uint64_t is_dh_modulus_found[NUM_THREADS];
pthread_mutex_t M_finders_mutex;

void* thread_function_checker(void* thread_input_buffer)
{
    uint64_t alert_ix;
    uint8_t  is_prime;    
    bigint   testing_M;                                                      
									 
    memcpy(&testing_M, thread_input_buffer, sizeof(bigint));               
    memcpy(&alert_ix, ((u8*)thread_input_buffer) + sizeof(bigint), sizeof(u64));
    is_prime = rabin_miller(&testing_M, RABIN_MILLER_PASSES);        
    if(is_prime){
	pthread_mutex_lock(&M_finders_mutex);
        is_dh_modulus_found[alert_ix] = 1;
        pthread_mutex_unlock(&M_finders_mutex);
    }                                                                      
									 
    return NULL;       
}

int main(void)
{
    void*     thread_func_inputs[NUM_THREADS];
    pthread_t thread_ids[NUM_THREADS];
    bigint    M;
    bigint    Q;
    bigint    one;
    bigint    two;
    bigint    tmp;
    bigint    aux;
    bigint    test_Ms[NUM_THREADS];
    FILE*     rand_fd = NULL;
    size_t    bytes_read;
    size_t    counter = 0;
    uint8_t   keep_searching = 1;
    uint8_t   is_prime = 0;

    pthread_mutex_init(&M_finders_mutex, NULL);

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

    /**************************   FIND Q   ***********************************/

    /* Generate random 320-bit prime Q. Set last and first bit to 1.      */
    /* This ensures it's really 320-bit and it's odd for prime potential. */

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
     * Instead of doing AUX += 2 for each one, generate new ~2700-bit AUX.
     * Also set AUX's first bit to ensure it really is a ~2700-bit number.
     * Clear its least significant bit to make it even, since we need
     * (Q * AUX) + 1 = possible 3072-bit prime M. Prime Q times even AUX will
     * make an even number, then +1 makes an odd number to check for primality.
     */
    for(uint64_t i = 0; i < NUM_THREADS; ++i)
    {
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

