#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include "../../../../src/lib/bigint.h"

int main(){
    uint64_t BIGINT_SIZ = 1200000; /* Better have this divisible by 8. */
    const size_t   total_ops  = 100;
    bigint   a;
    bigint   b;
    bigint   r;
    FILE*    ran = fopen("/dev/urandom", "r");
    double   time_taken = 0;    
    double   min_time = 10000000, max_time = 0, average_time = 0, total_time;
    double   times[total_ops];

    struct timeval tv1;
    struct timeval tv2;

    if(ran == NULL){ printf("[ERR] MUL Bench: fopen ran failed.\n"); return 1; }

    bigint_create(&a, BIGINT_SIZ,     0);
    bigint_create(&b, BIGINT_SIZ,     0);
    bigint_create(&r, BIGINT_SIZ * 2, 0);
   
    total_time = 0;

    for(size_t i = 0; i < total_ops; ++i){
        bigint_nullify(&a);
        bigint_nullify(&b);
        bigint_nullify(&r);
        fread(a.bits, 1, BIGINT_SIZ / 8, ran);
        fread(b.bits, 1, BIGINT_SIZ / 8, ran);
        a.used_bits = get_used_bits(a.bits, BIGINT_SIZ / 8);
        b.used_bits = get_used_bits(b.bits, BIGINT_SIZ / 8);
        a.free_bits = a.size_bits - a.used_bits;
        b.free_bits = b.size_bits - b.used_bits;

        gettimeofday(&tv1, NULL);
     
        bigint_mul_fast(&a, &b, &r);
        
        gettimeofday(&tv2, NULL);
        
        time_taken = ((double)(tv2.tv_usec - tv1.tv_usec) / 1000000)
                     + ((double)(tv2.tv_sec - tv1.tv_sec));

        if(time_taken < min_time){min_time = time_taken;}
        if(time_taken > max_time){max_time = time_taken;}
        times[i] = time_taken;
        total_time += time_taken;
        printf("MUL benchmark at [%03lu] of [%03lu]  ---  Two %lu-bit "
               "MUL operands. Time: %lf\n", i, total_ops, BIGINT_SIZ, times[i]
              );        
    }    

    average_time = total_time / total_ops;

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
          );
    printf("\n\n");
    printf("RESULTING TIMES:\n\n");
    printf("Minimum: %lf\n", min_time);
    printf("Maximum: %lf\n", max_time);
    printf("Average: %lf\n", average_time);

    return 0;
}
