#include "../../src/lib/bigint.h"

#define TEST_MAX_BYTES 512

void generate_and_add_large_ints(bigint* __restrict__ initial_kick,
                                 const uint64_t count)
{
    char filename[128];
    strcpy(filename, "../calc-results/add-test-0-result-my-0.dat\0");
    FILE* __restrict__ results_fd = NULL;

    bigint operand1;
    bigint operand2;
    bigint result;
    bigint temp_op1_mul;
    bigint temp_op2_mul;
    bigint ninety_big;
    bigint i_big;
    bigint temp1;
    bigint temp2;
    bigint temp3;
    bigint one;

    bigint_create_from_u32(&operand1,     TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&operand2,     TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&result,       TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&temp_op1_mul, TEST_MAX_BYTES * 8, 17000000);
    bigint_create_from_u32(&temp_op2_mul, TEST_MAX_BYTES * 8, 12111222);
    bigint_create_from_u32(&ninety_big,   TEST_MAX_BYTES * 8, 90);
    bigint_create_from_u32(&i_big,        TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&temp1,        TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&temp2,        TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&temp3,        TEST_MAX_BYTES * 8, 0);
    bigint_create_from_u32(&one,          TEST_MAX_BYTES * 8, 1);

    if( system("rm -f ../calc-results/add-test-0-result-my-*") < 0){
        printf("[ERR] Could not delete existing C code result DAT files.\n");
        exit(1);
    }

    for(uint64_t i = 0; i < count;  ++i){
        bigint_pow(&i_big, &ninety_big, &temp1);

        bigint_mul_fast(&temp1, &temp_op1_mul, &temp2);
        bigint_add_fast(&temp2, initial_kick, &temp3);
        bigint_sub_fast(&temp3, &i_big, &operand1);

        bigint_mul_fast(&temp1, &temp_op2_mul, &temp2);
        bigint_add_fast(&temp2, initial_kick, &temp3);
        bigint_sub_fast(&temp3, &i_big, &operand2);

        /* The big final addition to produce test results. */
        bigint_add_fast(&operand1, &operand2, &result);

        if(__builtin_expect((results_fd = fopen(filename, "a")) == NULL, 0)){
            perror("[ERR] fopen() failed. errno: ");
            exit(1);
        }
        if(__builtin_expect(fwrite(result.bits, 1, 405, results_fd) != 405, 0)){
            perror("[ERR] fwrite() failed. errno: ");
            exit(1);
        }

        fclose(results_fd);

        bigint_add_fast(&i_big, &one, &temp1);
        bigint_equate2(&i_big, &temp1);
    }

    return;
}

int main(){
    bigint start_bigint;
    bigint multiplier;
    bigint temp_mul_result;
    const uint64_t nr_add_results = 10000000;

    bigint_create_from_u32(&start_bigint,    TEST_MAX_BYTES * 8, 0xFF000000);
    bigint_create_from_u32(&multiplier,      TEST_MAX_BYTES * 8, 0xFF000000);
    bigint_create_from_u32(&temp_mul_result, TEST_MAX_BYTES * 8, 0);

    printf("Our own BigInt engine starting to generate test integers.\n");

    /* Loop will make a 100 * 32 ~= 3200-bit starting BigInt. */
    for(uint64_t i = 0; i < 100; ++i){
        bigint_mul_fast(&start_bigint, &multiplier, &temp_mul_result);
        bigint_equate2(&start_bigint, &temp_mul_result);
    }

    printf("Computed the initial kick number! Results calculation startingg\n");

    generate_and_add_large_ints(&start_bigint, nr_add_results);

    printf("BigInt ADD Test 1 - Own engine finished generating results.\n");

    return 0;
}
