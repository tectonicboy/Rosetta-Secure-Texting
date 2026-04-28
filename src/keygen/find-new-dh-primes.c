#include "../lib/rosetta-helpers.h"
#include "../lib/bigint.h"

//#define MAXIMUM_BITS        12000
//#define SIZE_Q_BITS         320
//#define SIZE_Q_BYTES        40
//#define SIZE_M_BITS         3072
//#define SIZE_M_BYTES        384
//#define RABIN_MILLER_PASSES 64
//#define NUM_THREADS         24

/* Command-line arguments expected:
 * - Bitwidth of prime order Q
 * - Bitwidth of prime modulus M
 * - Number of Rabin-Miller passes before a number is safely considered prime.
 * - Number of threads to use (primes checked in parallel)
 */
#define REQ_NUM_CMD_LINE_ARGS 4
unsigned long rabin_miller_passes;
uint64_t* is_dh_modulus_found;
pthread_mutex_t M_finders_mutex;

void* thread_function_checker(void* thread_input_buffer)
{
    uint64_t alert_ix;
    uint8_t  is_prime;
    bigint   testing_M;

    memcpy(&testing_M, thread_input_buffer, sizeof(bigint));
    memcpy(&alert_ix, ((u8*)thread_input_buffer) + sizeof(bigint), sizeof(u64));
    is_prime = rabin_miller(&testing_M, rabin_miller_passes);
    if(is_prime){
        pthread_mutex_lock(&M_finders_mutex);
        is_dh_modulus_found[alert_ix] = 1;
        pthread_mutex_unlock(&M_finders_mutex);
    }

    return NULL;
}

int main(int argc, char* argv[])
{
    void**     thread_func_inputs;
    pthread_t* thread_ids;
    bigint     M;
    bigint     Q;
    bigint     one;
    bigint     two;
    bigint     tmp;
    bigint     aux;
    bigint*    test_Ms;
    FILE*      rand_fd = NULL;
    size_t     bytes_read;
    size_t     counter = 0;
    uint8_t    keep_searching = 1;
    uint8_t    is_prime = 0;
		uint8_t    unused_bits_m = 0;
		uint8_t    unused_bits_q = 0;
		uint8_t    unused_bits_aux = 0;
    unsigned long q_bits;
		unsigned long m_bits;
		unsigned long num_threads;
		unsigned long q_bytes;
		__attribute__((unused)) unsigned long m_bytes;
		unsigned long aux_bits;
		unsigned long aux_bytes;
		unsigned long max_reserved_bits;


		/* These will now be taken as command-line arguments.
     *
		 * #define SIZE_Q_BITS         320
     * #define SIZE_M_BITS         3072
     * #define RABIN_MILLER_PASSES 64
     * #define NUM_THREADS         24
		 *
		 * Then Q_bytes, M_bytes and MAX_FREE_BITS will be computed from these.
     */
		/* +1 because the shell already passes the first command-line argument, that
		 * being the command with which the program was started. The rest are the
		 * command-line arguments that the user actually passed when running it.
		 */
    if(argc != REQ_NUM_CMD_LINE_ARGS + 1){
        printf(
				  "To run the finder, please pass %u non-zero command-line arguments:\n"
					"  - Required bitwidth of prime order Q;\n"
					"  - Required bitwidth of modulus M, where Q exactly divides (M-1);\n"
					"  - Rabin-Miller passes to run before considering a number prime;\n"
					"  - Number of CPU threads (checks that many moduli in parallel).\n\n"
					"Typical example: bin/keygen/find-new-dh-primes 320 3072 50 16\n\n",
				  REQ_NUM_CMD_LINE_ARGS);
				exit(1);
		}

		/* Parse the command-line arguments.
		 * Since strtoul can actually return 0 or ULONG_MAX both on success and on
		 * error, reset errno to 0 here, so the call can properly handle errors.
		 */
		errno = 0;
    q_bits = strtoul(argv[1], NULL, 10);
		m_bits = strtoul(argv[2], NULL, 10);
		rabin_miller_passes = strtoul(argv[3], NULL, 10);
		num_threads = strtoul(argv[4], NULL, 10);
    if(q_bits == 0 || m_bits == 0 ||
			 rabin_miller_passes == 0 || num_threads == 0 ||
			 errno != 0)
		{
        printf("One or more command-line arguments are wrong. Try again.\n");
        exit(1);
		}
		{
		    unsigned long temp_m_bits = m_bits;
				unsigned long temp_q_bits = q_bits;
			  while(temp_m_bits++ % 8 != 0){
				    ++unused_bits_m;
				}
			 	m_bytes = temp_m_bits / 8;
				while(temp_q_bits++ % 8 != 0){
				    ++unused_bits_q;
				}
				q_bytes = temp_q_bits / 8;
				max_reserved_bits = m_bits * 8;
		}

    thread_func_inputs  = (void**)    malloc(num_threads * sizeof(void*));
    thread_ids          = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
    test_Ms             = (bigint*)   malloc(num_threads * sizeof(bigint));
		is_dh_modulus_found = (uint64_t*) malloc(num_threads * sizeof(uint64_t));

    pthread_mutex_init(&M_finders_mutex, NULL);

		bigint_create_from_u32(&M,   max_reserved_bits, 0);
    bigint_create_from_u32(&Q,   max_reserved_bits, 0);
    bigint_create_from_u32(&one, max_reserved_bits, 1);
    bigint_create_from_u32(&two, max_reserved_bits, 2);
    bigint_create_from_u32(&tmp, max_reserved_bits, 0);
    bigint_create_from_u32(&aux, max_reserved_bits, 0);

		for(uint64_t i = 0; i < num_threads; ++i){
        bigint_create_from_u32(&(test_Ms[i]), max_reserved_bits, 0);
        thread_func_inputs[i] = calloc( 1, sizeof(uint64_t) + sizeof(bigint) );
        is_dh_modulus_found[i] = 0;
    }

    /**************************   FIND Q   ***********************************/

    /* Generate random 320-bit prime Q. Set last and first bit to 1.      */
    /* This ensures it's really 320-bit and it's odd for prime potential. */

    rand_fd = fopen(DEV_URANDOM_PATH, "r");
    if(rand_fd == NULL){
        printf("[ERR]  Q  fopen() failed.\n");
        goto label_cleanup;
    }
    bytes_read = fread(Q.bits, 1, q_bytes, rand_fd);
    if(bytes_read != q_bytes){
        printf("[ERR]  Q  fread() failed.\n");
        goto label_cleanup;
    }
		/* Clear all bits more significant than the bitwidth requested. */
		/* Set the most significant requested bit too. */
    for(uint8_t i = 1; i <= unused_bits_q; ++i){
        Q.bits[q_bytes - 1] &= ~(1 << (7 - unused_bits_q + i));
		}
    Q.bits[q_bytes - 1] |= (1 << (7 - unused_bits_q));
    Q.bits[0] |= (1 << 0);
    Q.used_bits = get_used_bits(Q.bits, q_bytes);

    while(is_prime == 0){
        printf("Finding 320-bit prime  Q  --  numbers checked: %lu\n", counter);
        is_prime = rabin_miller(&Q, rabin_miller_passes);
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
    aux_bits = m_bits - q_bits;
		{
			  unsigned long temp_aux_bits = aux_bits;
			  while(temp_aux_bits++ % 8 != 0){
            ++unused_bits_aux;
			  }
				aux_bytes = temp_aux_bits / 8;
		}
    printf("\n\n============ STARTING TO FIND 3072-BIT  M  ==============\n\n");

label_keep_searching:

    /* Prepare test M's for each thread to check.
     * Instead of doing AUX += 2 for each one, generate new ~(m - q)-bit AUX.
     * Also set AUX's first bit to ensure it really is a ~(m - q)-bit number.
     * Clear its least significant bit to make it even, since we need
     * (Q * AUX) + 1 = possible prime M. Prime Q times even AUX will
     * make an even number, then +1 makes an odd number to check for primality.
     */
    for(uint64_t i = 0; i < num_threads; ++i)
    {
        memset(aux.bits, 0x00, aux_bytes);
        bytes_read = fread(aux.bits, 1, aux_bytes, rand_fd);
        if(bytes_read != aux_bytes){
            printf("[ERR]  AUX  fread() failed.\n");
            goto label_cleanup;
        }
				for(uint8_t x = 1; x <= unused_bits_aux; ++x){
            aux.bits[aux_bytes - 1] &= ~(1 << (7 - unused_bits_aux + x));
				}
        aux.bits[aux_bytes - 1] |= (1 << (7 - unused_bits_aux));
        aux.bits[0] &= ~(1 << 0);
        aux.used_bits = get_used_bits(aux.bits, aux_bytes);
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

    for(uint64_t i = 0; i < num_threads; ++i){
        memcpy(thread_func_inputs[i], &(test_Ms[i]), sizeof(bigint));
        memcpy(((u8*)thread_func_inputs[i]) + sizeof(bigint), &i, sizeof(u64));

        pthread_create( &(thread_ids[i])
                       ,NULL
                       ,thread_function_checker
                       ,thread_func_inputs[i]
                      );
    }

    for(uint64_t i = 0; i < num_threads; ++i){
        pthread_join(thread_ids[i], NULL);
    }

    counter += num_threads;

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    SET_PRINT_BG_CYAN
    printf(PRINT_RED("\n[%d-%02d-%02d %02d:%02d:%02d] ")
           ,tm.tm_year + 1900,tm.tm_mon + 1, tm.tm_mday
           ,tm.tm_hour, tm.tm_min, tm.tm_sec
          );
    SET_PRINT_BG_BLACK

    printf("All %lu threads finished.\n"
					 "Discoveries: [", num_threads);

    for(uint64_t i = 0; i < num_threads; ++i){
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
    if(rand_fd != NULL){
        fclose(rand_fd);
		}
    bigint_cleanup(&M);
    bigint_cleanup(&Q);
    bigint_cleanup(&two);
    bigint_cleanup(&aux);
    bigint_cleanup(&tmp);
    bigint_cleanup(&one);
    for(uint64_t i = 0; i < num_threads; ++i){
        free(thread_func_inputs[i]);
        bigint_cleanup(&(test_Ms[i]));
    }
    free(thread_func_inputs);
    free(thread_ids);
    free(test_Ms);
		free(is_dh_modulus_found);
    return 0;
}
