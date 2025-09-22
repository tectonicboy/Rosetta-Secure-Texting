#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <float.h> /* for DBL_MAX */

#include "../../../../src/lib/bigint.h"

int main(){
    uint64_t BIGINT_SIZ = 3072; /* Better have this divisible by 8. */
    size_t   total_ops  = 10000000;
    bigint   a;
    bigint   b;
    bigint   r;
    FILE*    ran = fopen("/dev/urandom", "r");
    double   time_taken = 0;    
    double   min_time;
    double   max_time;
    double   average_time = 0;
    double   total_time;
    double*  times = (double*)calloc(1, total_ops * sizeof(double));
    size_t   print_step = total_ops / 100;
    uint8_t  progress_percent = 0;

    struct timeval tv1;
    struct timeval tv2;

    if(ran == NULL){ printf("[ERR] MUL Bench: fopen ran failed.\n"); return 1; }

    bigint_create(&a, BIGINT_SIZ,     0);
    bigint_create(&b, BIGINT_SIZ,     0);
    bigint_create(&r, BIGINT_SIZ * 2, 0);
   
    total_time = 0;

    time_t t = time(NULL);                                                   
    struct tm tm = *localtime(&t);
    
    printf("\n\n----->  [%d-%02d-%02d %02d:%02d:%02d]  Starting.  <-----\n\n"
           ,tm.tm_year + 1900,tm.tm_mon + 1, tm.tm_mday                          
           ,tm.tm_hour, tm.tm_min, tm.tm_sec 
          );
    printf("**************************************************************\n"    
           "*                                                            *\n"    
           "*                  BENCHMARK STARTING                        *\n"    
           "*                                                            *\n"
           "*                      BigInt MUL                            *\n"
           "*                                                            *\n"
           "**************************************************************\n"    
           "\n\n"
          );

    min_time         = DBL_MAX;
    max_time         = 0;
    total_time       = 0;
    progress_percent = 0;

    for(size_t i = 0; i < total_ops; ++i){
        bigint_nullify(&a);
        bigint_nullify(&b);
        bigint_nullify(&r);

        if(fread(a.bits, 1, BIGINT_SIZ / 8, ran) != (BIGINT_SIZ / 8))
            printf("\n\n   ----->  [ERR] fread() failed!  <-----\n\n");
        if(fread(b.bits, 1, BIGINT_SIZ / 8, ran) != (BIGINT_SIZ / 8))
            printf("\n\n   ----->  [ERR] fread() failed!  <-----\n\n");

        a.used_bits = get_used_bits(a.bits, BIGINT_SIZ / 8);
        b.used_bits = get_used_bits(b.bits, BIGINT_SIZ / 8);
        a.free_bits = a.size_bits - a.used_bits;
        b.free_bits = b.size_bits - b.used_bits;

        gettimeofday(&tv1, NULL);
     
        bigint_mul_fast(&a, &b, &r);
        
        gettimeofday(&tv2, NULL);
    
		if(tv1.tv_sec == tv2.tv_sec){    
	        time_taken = ((double)(tv2.tv_usec - tv1.tv_usec));
		}
        else{
			//time_taken = 1000000.0 - (double)tv1.tv_usec +(double)tv2.tv_usec;
             time_taken = (total_time / i);
		}

        
        times[i] = time_taken;
        total_time += time_taken;
  
        if( __builtin_expect( ((i % print_step) == 0) && (i > 0), 0) ){

            progress_percent += 1;

            t = time(NULL);                                                   
            tm = *localtime(&t);                                           
            printf("[%d-%02d-%02d %02d:%02d:%02d] ", tm.tm_year + 1900
                  ,tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
                  );
        
            printf(" %03u %%\tcomplete  --  AVG Time: %lf micros.\n"
                   ,progress_percent, (total_time / i)
                  );
        }
    }    

    average_time = total_time / total_ops;

    printf("Reporting measurement type 1 AVG time: %lf\n", average_time);
    
/******************************************************************************/

    total_time       = 0;
    progress_percent = 0;

    size_t batch_size = 100000;


	/* Allocate and initialize 100K bigints. */

	bigint* batch_op1 = (bigint*)calloc(1, batch_size * sizeof(bigint));
	bigint* batch_op2 = (bigint*)calloc(1, batch_size * sizeof(bigint));
	bigint* batch_res = (bigint*)calloc(1, batch_size * sizeof(bigint));

	for(size_t j = 0; j < batch_size; ++j){
		bigint_create(batch_op1 + j, BIGINT_SIZ,     0);
		bigint_create(batch_op2 + j, BIGINT_SIZ,     0);
		bigint_create(batch_res + j, BIGINT_SIZ * 2, 0);

		if(fread(batch_op1[j].bits, 1, BIGINT_SIZ / 8, ran) != (BIGINT_SIZ / 8))
			printf("\n\n   ----->  [ERR] fread() failed!  <-----\n\n");
		if(fread(batch_op2[j].bits, 1, BIGINT_SIZ / 8, ran) != (BIGINT_SIZ / 8))
			printf("\n\n   ----->  [ERR] fread() failed!  <-----\n\n");

		batch_op1[j].used_bits = get_used_bits(batch_op1[j].bits, BIGINT_SIZ/8);
		batch_op2[j].used_bits = get_used_bits(batch_op2[j].bits, BIGINT_SIZ/8);
		batch_op1[j].free_bits = batch_op1[j].size_bits -batch_op1[j].used_bits;
		batch_op2[j].free_bits = batch_op2[j].size_bits -batch_op2[j].used_bits;

	}

	gettimeofday(&tv1, NULL);

	for(size_t j = 0; j < batch_size; ++j){
		bigint_mul_fast(batch_op1 + j, batch_op2 + j, batch_res + j);
    }

    gettimeofday(&tv2, NULL);

    printf( "\n WAY 2  |||  %lf sec  |||  %lf -> %lf micros\n\n"
           ,(double)tv2.tv_sec - (double)tv1.tv_sec
           ,(double)tv1.tv_usec, (double)tv2.tv_usec
          );

    printf("Measurement Type 2 total ops uninterrupted : %lu\n", batch_size);


    for(size_t j = 0; j < batch_size; ++j){
	    free(batch_op1[j].bits);
	    free(batch_op2[j].bits);
	    free(batch_res[j].bits);
	}
	
    free(batch_op1);
	free(batch_op2);
	free(batch_res);      

			

/******************************************************************************/
    fclose(ran);
    free(a.bits);
    free(b.bits);
    free(r.bits);    
    printf("\n\n");
    printf("**************************************************************\n"
           "*                                                            *\n"
           "*                  BENCHMARK FINISHED                        *\n"
           "*                                                            *\n"
           "**************************************************************\n"
           "\n\n"
          );

    printf( "Description: BigInt MUL  --  %lu * %lu   bit numbers.\n"
           ,BIGINT_SIZ, BIGINT_SIZ
          );

    printf("\n\n");
    printf("RESULTING TIMES:\n\n");
    //printf("Minimum: %lf micros\n", min_time    );
    //printf("Maximum: %lf micros\n", max_time    );
    printf("MULs total  : %lu\n", total_ops);
    printf("Time_Total  : %lf seconds\n", total_time / 1000000);
    printf("Time_Average: %lf micros\n\n", average_time);
    free(times);

    return 0;
}
