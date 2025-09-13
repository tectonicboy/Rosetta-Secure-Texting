#include "../lib/bigint.h"

/******************************************************************************/

#define MAXIMUM_BITS        12000
#define SIZE_Q_BITS         320
#define SIZE_Q_BYTES        40
#define SIZE_M_BITS         3072
#define SIZE_M_BYTES        384
#define RABIN_MILLER_PASSES 64


int main(void){

    bigint M;
    bigint Q;
    bigint two;
    bigint tmp;

    FILE* rand_fd = NULL;

    size_t bytes_read;
    size_t counter = 0;

    uint8_t is_prime = 0;

    bigint_create(&M,   MAXIMUM_BITS, 0);
    bigint_create(&Q,   MAXIMUM_BITS, 0);
    bigint_create(&two, MAXIMUM_BITS, 2);
    bigint_create(&tmp, MAXIMUM_BITS, 0);

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
    Q.free_bits = Q.size_bits - Q.used_bits;

    while(is_prime == 0){
        is_prime = rabin_miller(&Q, RABIN_MILLER_PASSES);
        ++counter;
        printf("Finding 320-bit prime  Q  --  checked %lu numbers.\n", counter);
        bigint_equate2(&tmp, &Q);
        bigint_add_fast(&tmp, &two, &Q);
    }


    /* For finding M. */
    is_prime = 0;
    counter  = 0;

    /**************************************************************************/

	printf("\n\n============ STARTING TO FIND 3072-BIT  M  ==============\n\n");

    bytes_read = fread(M.bits, 1, SIZE_M_BYTES, rand_fd);
	if(bytes_read != SIZE_M_BYTES){
		printf("[ERR]  M  fread() failed.\n");
		goto label_cleanup;
	}    

	M.bits[SIZE_M_BYTES - 1] |= (1 << 7);
	M.bits[0] |= (1 << 0);

	M.used_bits = get_used_bits(M.bits, SIZE_M_BYTES);
	M.free_bits = M.size_bits - M.used_bits;

	while(is_prime == 0){
		is_prime = rabin_miller(&M, RABIN_MILLER_PASSES);
		++counter;
		printf("Finding 3072-bit prime M  --  checked %lu numbers.\n", counter);
		bigint_equate2(&tmp, &M);
		bigint_add_fast(&tmp, &two, &M);
	}

label_cleanup:
    
    if(rand_fd != NULL)
        fclose(rand_fd);

    free(M.bits);
    free(Q.bits);
    free(two.bits);
    free(tmp.bits);

    return 0;
}

