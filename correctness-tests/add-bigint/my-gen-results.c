#include "../../src/lib/bigint.h"

#define TEST_MAX_BYTES 512

void generate_and_add_large_ints(bigint*  initial_kick, 
                                 uint64_t count, 
                                 uint64_t nr_operand_bits)
{
    char filename[128];
    strcpy(filename, "../calc-results/add-test-0-result-my-0.dat\0");
    FILE* results_fd = NULL;

    bigint operand1;
    bigint operand2;
    bigint result;
    bigint temp_op1_mul;
    bigint temp_op2_mul;
    bigint ninety_big;
    bigint i_big;
    bigint temp1;
    bigint temp2;
    bigint one;

    bigint_create(&operand1,     TEST_MAX_BYTES * 8, 0);
    bigint_create(&operand2,     TEST_MAX_BYTES * 8, 0);
    bigint_create(&result,       TEST_MAX_BYTES * 8, 0);
    bigint_create(&temp_op1_mul, TEST_MAX_BYTES * 8, 17000000);
    bigint_create(&temp_op2_mul, TEST_MAX_BYTES * 8, 12111222);
    bigint_create(&ninety_big,   TEST_MAX_BYTES * 8, 90);
    bigint_create(&i_big,        TEST_MAX_BYTES * 8, 0);
    bigint_create(&temp1,        TEST_MAX_BYTES * 8, 0);
    bigint_create(&temp2,        TEST_MAX_BYTES * 8, 0);
    bigint_create(&one,          TEST_MAX_BYTES * 8, 1);

    printf("[DEBUG] strlen(filename) = %lu\n", strlen(filename));

    if( system("rm -f ../calc-results/add-test-0-result-my-*") < 0){
        printf("[ERR] Could not delete existing C code result DAT files.\n");
        exit(1);
    }
   
    for(uint64_t i = 0; i < count;  ++i){
        bigint_add_fast(&i_big, &one, &temp1);
        bigint_equate2(&i_big, &temp1);
        bigint_pow(&i_big, &ninety_big, &temp1);

        bigint_mul_fast(&temp1, &temp_op1_mul, &temp2);
        bigint_add_fast(&temp2, initial_kick, &operand1);

        bigint_mul_fast(&temp1, &temp_op2_mul, &temp2);
        bigint_add_fast(&temp2, initial_kick, &operand2);

        /* The big final addition to produce test results. */
        bigint_add_fast(&operand1, &operand2, &result);

        /* Store in a file for checking with python's builtin bigint engine. */
        /* Retarded way to do it but will do for now. */
        if( i > 0 && (i % (count/10) == 0) ){
            printf("Reached %lu results! New file DAT starting.\n", i);
            if(i / (count/10) == 1.0) { filename[strlen(filename) - 5] = '1'; }
            if(i / (count/10) == 2.0) { filename[strlen(filename) - 5] = '2'; }
            if(i / (count/10) == 3.0) { filename[strlen(filename) - 5] = '3'; }
            if(i / (count/10) == 4.0) { filename[strlen(filename) - 5] = '4'; }
            if(i / (count/10) == 5.0) { filename[strlen(filename) - 5] = '5'; }
            if(i / (count/10) == 6.0) { filename[strlen(filename) - 5] = '6'; }
            if(i / (count/10) == 7.0) { filename[strlen(filename) - 5] = '7'; }
            if(i / (count/10) == 8.0) { filename[strlen(filename) - 5] = '8'; }
            if(i / (count/10) == 9.0) { filename[strlen(filename) - 5] = '9'; }
        }
        
        results_fd = fopen(filename, "a");
        if(results_fd == NULL){
            perror("[ERR] fopen() failed. errno: ");
            exit(1);
        }
        if( fwrite(result.bits, 1, 405, results_fd) != 405){
            perror("[ERR] fwrite() failed. errno: ");
            exit(1);
        }
        
        fclose(results_fd);
    }

    return;
}

int main(){
    bigint start_bigint;
    bigint multiplier;
    bigint temp_mul_result;
    uint64_t operand_bits = 32;
    uint64_t nr_add_results = 10000000;

    bigint_create(&start_bigint,    TEST_MAX_BYTES * 8, 0xFF000000);
    bigint_create(&multiplier,      TEST_MAX_BYTES * 8, 0xFF000000);
    bigint_create(&temp_mul_result, TEST_MAX_BYTES * 8, 0);

    printf("Our own BigInt engine starting to generate test integers.\n");

    /* Loop will make a 100 * 32 ~= 3200-bit starting BigInt. */
    for(uint64_t i = 0; i < 100; ++i){
        bigint_mul_fast(&start_bigint, &multiplier, &temp_mul_result);
        bigint_equate2(&start_bigint, &temp_mul_result);
        operand_bits += 32;
    }

    printf("Computed the initial kick number! Results calculation startingg\n");

    generate_and_add_large_ints(&start_bigint, nr_add_results, operand_bits);
    
    return 0;
}
