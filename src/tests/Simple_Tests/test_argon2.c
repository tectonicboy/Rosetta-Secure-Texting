#include "../../lib/cryptolib.h"

#define RESBITS 12800

int main(){

/********** NOW TESTING ARGON2id ****************/
    
    struct Argon2_parms prms;
    
    double cpu_time_used_argon2;
    clock_t start, end;
    
    /* small, fast -- as in RFC test vector */
    
    /*
    prms.p = 4;   
    prms.T = 32;  
    prms.m = 32;
    prms.t = 3;  
    prms.v = 19;  
    prms.y = 2;  
    */
    
    
    /* big, slow - as used in Rosetta */
    
    
    prms.p = 8;   
    prms.T = 64;  
    prms.m = 2097000;  
    prms.t = 1;  
    prms.v = 19;  
    prms.y = 2;  
    
    
    u8   *P = malloc(32),
         *S = malloc(16),
         *K = malloc(8),
         *X = malloc(12);
         
    memset(P, 0x01, 32);     
    memset(S, 0x02, 16);
    memset(K, 0x03, 8 );
    memset(X, 0x04, 12);
    
    prms.P = P;
    prms.S = S;
    prms.K = K;
    prms.X = X;
    
    prms.len_P = 32;
    prms.len_S = 16;
    prms.len_K = 8 ;
    prms.len_X = 12;
    
    u8* argon2_output_tag = malloc(prms.T);
    
    start = clock();
    
    Argon2_MAIN(&prms, argon2_output_tag);
    
    end = clock();
    
    cpu_time_used_argon2 = ((double) (end - start)) / CLOCKS_PER_SEC; 
    
    printf("\n\n***** ARGON2id produced %lu-byte Tag: ******\n\n", prms.T);
    
    for(uint32_t i = 0; i < prms.T; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)argon2_output_tag[i]);
    }
    printf("\n\n");
    
    printf("TOTAL TIME for Argon2: %lf seconds\n\n"
            , cpu_time_used_argon2 / (double)prms.p);
    
    free(P); free(S); free(K); free(X); free(argon2_output_tag);
    
    return 0;
}
