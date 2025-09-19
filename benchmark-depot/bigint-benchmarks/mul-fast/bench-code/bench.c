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
    size_t   print_step = total_ops / 10;
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
        
        time_taken = ((double)(tv2.tv_usec - tv1.tv_usec) / 1000000.0)
                     + ((double)(tv2.tv_sec - tv1.tv_sec));

        int64_t microsecs = tv2.tv_usec - tv1.tv_usec;

        if(time_taken < min_time){ 
            printf("\n[op %lu] New MIN time. OLD min: %lf  --  NEW min: %lf\n\n"
                   ,i, min_time, time_taken
                  );
            min_time = time_taken; 
        }
        if(time_taken > max_time){ 
            printf("\n[op %lu] New MAX time. OLD max: %lf  --  NEW max: %lf\n\n"  
                   ,i, max_time, time_taken                                      
                  );
            max_time = time_taken; 
        }
        
        times[i] = time_taken;
        total_time += time_taken;
  
        if( __builtin_expect( ((i % print_step) == 0) && (i > 0), 0) ){

            progress_percent += 10;

            t = time(NULL);                                                   
            tm = *localtime(&t);                                           
            printf("[%d-%02d-%02d %02d:%02d:%02d] ", tm.tm_year + 1900               
                   ,tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec      
                  );                                                                 
        
            printf("Done ops \t%lu\t  --  AVG Time: %lf nanos  --  %u %% done. usec = %lu\n"
                   ,i, (total_time / i) * 1000000000, progress_percent, microsecs
                  );        
        }
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
           "\n\n"
          );

    printf( "Description: BigInt MUL  --  %lu * %lu   bit numbers.\n"
           ,BIGINT_SIZ, BIGINT_SIZ
          );

    printf("\n\n");
    printf("RESULTING TIMES:\n\n");
    printf("Minimum: %lf nanos\n", min_time     * 1000000000);
    printf("Maximum: %lf nanos\n", max_time     * 1000000000);
    printf("Average: %lf nanos\n", average_time * 1000000000);
    printf("\n");
    printf("Total: %lf seconds\n\n", total_time);
    free(times);

    return 0;
}
