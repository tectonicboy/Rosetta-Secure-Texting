#include "../../lib/cryptolib.h"

#define MAX_BIGINT_SIZ 12800
#define PRIVKEY_LEN    40
#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))
#define TEST_DATA_LEN  1024

int main(){

    struct bigint *M, *Q, *G, *Gm, *Am, *a, *s, *e;
    
    clock_t time;
    double total_time_sec;
    
    /* Text bytes to be signed */    
    uint8_t* msg = calloc(1, TEST_DATA_LEN);
    FILE* ran = NULL;
    size_t status;
    uint8_t* result_signature = calloc(1, SIGNATURE_LEN);
    uint8_t isValid;

    ran = fopen("/dev/urandom","r");
    
    status = fread(msg, 1, TEST_DATA_LEN, ran);
    
    if(status != TEST_DATA_LEN){
        printf("[ERR] TEST SIG_GEN: Failed to read urandom. Quitting.\n\n");
        return 1;
    }
    
    fclose(ran);

    M = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_M.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     ); 
       
    Q = get_bigint_from_dat
     ( 320
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_Q.dat"
      ,320
      ,MAX_BIGINT_SIZ
     );
                            
    G = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_G.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    Gm = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_Gm.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
   
    a = get_bigint_from_dat
    ( 320
     ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/server_privkey.dat"
     ,318
     ,MAX_BIGINT_SIZ
    );

    Am = get_bigint_from_dat
    ( 3072
     ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin"
        "/server_pubkeymont.dat" 
     ,3071
     ,MAX_BIGINT_SIZ
    );
             
    printf("Result of compare(G, a) : %u\n\n", bigint_compare2(G, a));

    printf("Generating signatures...\n\n");
    
    for(uint64_t i = 0; i < 20; ++i){
        time = clock();
        
        signature_generate( M, Q, Gm, msg, TEST_DATA_LEN
                           ,result_signature, a, PRIVKEY_LEN
                          );
        
        time = clock() - time;
        total_time_sec = ((double)time)/CLOCKS_PER_SEC;
        printf("Time taken for Sig_GEN[%lu]: %lf sec.\n\n", i, total_time_sec);
    }
    
    printf("\nFinished the signatures!\n\n");
 
    s = (struct bigint *)(result_signature + 0);
    e = (struct bigint *)(result_signature + sizeof(bigint) + PRIVKEY_LEN);    
    
    s->bits = calloc(1, (size_t)(s->size_bits / 8));
    e->bits = calloc(1, (size_t)(e->size_bits / 8));
 
    memcpy( s->bits 
           ,result_signature + (1*sizeof(struct bigint)) +  0
           ,PRIVKEY_LEN
          );
     
    memcpy( e->bits
           ,result_signature + (2*sizeof(struct bigint)) + PRIVKEY_LEN
           ,PRIVKEY_LEN
          );
    
    /*
    printf("Reconstructed BigInts s and e from what's in the signature.\n");  
      
    printf("\ns: \n");   
    bigint_print_info(s);
    bigint_print_bits(s);
  
    printf("\ne:\n");
    bigint_print_info(e);
    bigint_print_bits(e);
   
    printf("Ready to call SIGNATURE VALIDATE now!\n");
    */
    time = clock();

    isValid = signature_validate(Gm, Am, M, Q, s, e, msg, TEST_DATA_LEN);
    
    time = clock() - time;
    total_time_sec = ((double)time)/CLOCKS_PER_SEC;
    printf("Time taken for Sig_VAL: %lf sec.\n\n", total_time_sec);
    
    
    if(isValid == 1){
        printf("Valid Signature: NO\n");
    }
    else{
        printf("Valid Signature: YES\n");
    }
    
    return 0; 
}
