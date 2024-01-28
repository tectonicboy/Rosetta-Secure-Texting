#include <string.h>
#include "bigint.h"
#include <stdint.h>



int main(){

	/* TESTING BIGINT_GET_BIT() PARAMETERIZED MACRO!! */

	struct bigint *eleven = malloc(sizeof(struct bigint))
			     ,*twelve = malloc(sizeof(struct bigint))
			     ,*result = malloc(sizeof(struct bigint))
			     ;

	bigint_create(eleven, 64000, 11);
	bigint_create(twelve, 64000, 12);
	bigint_create(result, 64000, 0 );
	
	uint8_t bitA, bitB, bitC, bitD;

	bigint_pow(eleven, twelve, result);
	
	/* Should come out as 1. */
	BIGINT_GET_BIT(*eleven, 0, bitA);
	
	/* Should come out as 0. */
	BIGINT_GET_BIT(*twelve, 0, bitB);
	
	/* 1. */
	BIGINT_GET_BIT(*result, 29, bitC);
	
	uint64_t i = 40;
	
	/* zero. */
	BIGINT_GET_BIT(*result, i, bitD);
	
	printf(
		"OBTAINED BITS FROM MACRO:\n\n"
		"bit[0]  of    11 = %u  (Should be 1)\n"
		"bit[0]  of    12 = %u  (Should be 0)\n"
		"bit[29] of 11^12 = %u  (Should be 1)\n"
		"bit[40] of 11^12 = %u  (Should be 0)\n"
		,bitA, bitB, bitC, bitD
	);
	
	return 0;
}
