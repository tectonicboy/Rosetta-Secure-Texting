#include "bigint.h"

#define TEST_MAX_BITS 12800

int main(){
	struct bigint a, b, c, d, e, zero, one, two, res, rem;
	
	bigint_create(&a, 	 TEST_MAX_BITS, 1000000077);
	bigint_create(&b, 	 TEST_MAX_BITS, 4096);
	bigint_create(&c, 	 TEST_MAX_BITS, 25);
	bigint_create(&d, 	 TEST_MAX_BITS, 8);
	bigint_create(&e, 	 TEST_MAX_BITS, (uint32_t)(pow(2, 16) - 1));
	bigint_create(&res,  TEST_MAX_BITS, 0);
	bigint_create(&rem,  TEST_MAX_BITS, 0);
	bigint_create(&zero, TEST_MAX_BITS, 0);
	bigint_create(&one,  TEST_MAX_BITS, 1);
	bigint_create(&two,  TEST_MAX_BITS, 2);
	

	
	struct bigint big1, big2, bigres, bigrem;
	
	bigint_create(&big1,   TEST_MAX_BITS, 0);
	bigint_create(&big2,   TEST_MAX_BITS, 0);
	bigint_create(&bigres, TEST_MAX_BITS, 0);
	bigint_create(&bigrem, TEST_MAX_BITS, 0);
	
	bigint_pow(&b, &c, &big1);
	bigint_pow(&a, &d, &big2);
	
	bigint_div2(&big1, &big2, &bigres, &bigrem);
	
	printf("BIG RESULT:\n");
	bigint_print_info(&bigres);
	bigint_print_bits(&bigres);
	
	printf("BIG REMAINDER:\n");
	bigint_print_info(&bigrem);
	bigint_print_bits(&bigrem);
	
	bigint_div2(&c, &d, &bigres, &bigrem);
	
	printf("(25 ÷ 8) BIG RESULT:\n");
	bigint_print_info(&bigres);
	bigint_print_bits(&bigres);
	
	printf("(25 ÷ 8) BIG REMAINDER:\n");
	bigint_print_info(&bigrem);
	bigint_print_bits(&bigrem);
	
	bigint_div2(&c, &c, &bigres, &bigrem);
	
	printf("(25 ÷ 25) BIG RESULT:\n");
	bigint_print_info(&bigres);
	bigint_print_bits(&bigres);
	
	printf("(25 ÷ 25) BIG REMAINDER:\n");
	bigint_print_info(&bigrem);
	bigint_print_bits(&bigrem);
	
	bigint_div2(&d, &c, &bigres, &bigrem);
	
	printf("(8 ÷ 25) BIG RESULT:\n");
	bigint_print_info(&bigres);
	bigint_print_bits(&bigres);
	
	printf("(8 ÷ 25) BIG REMAINDER:\n");
	bigint_print_info(&bigrem);
	bigint_print_bits(&bigrem);
	
	return 0;
}
