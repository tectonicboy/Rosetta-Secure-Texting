#include "../../lib/cryptolib.h"

#define MAX_BIGINT_SIZ 12800
#define PRIVKEY_LEN    40 
#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))

int main(){

    struct bigint *M, *Q, *G, *Gm, *Am, *a, *s, *e;
    
    clock_t time;
    double total_time_sec;
    
    /* Text bytes to be signed */    
    const uint64_t data_len = 197; 
    uint8_t* msg = calloc(1, data_len);
    FILE* ran = NULL;
    size_t status;
    uint8_t* result_signature = calloc(1, SIGNATURE_LEN);
    uint8_t isValid;

    ran = fopen("/dev/urandom","r");
    
    status = fread(msg, 1, 197, ran);
    
    if(status != 197){
        printf("[ERR] TEST SIG_GEN: Failed to read urandom. Quitting.\n\n");
        return 1;
    }
    
    fclose(ran);

    M  = get_BIGINT_from_DAT( 3072
                             ,"../saved_nums/saved_M.dat\0"
                             ,3071
                             ,MAX_BIGINT_SIZ
                            ); 
       
    Q  = get_BIGINT_from_DAT( 320
                             ,"../saved_nums/saved_Q.dat\0"
                             ,320
                             ,MAX_BIGINT_SIZ
                            );
                            
    G  = get_BIGINT_from_DAT( 3072
                             ,"../saved_nums/saved_G.dat\0"
                             ,3071
                             ,MAX_BIGINT_SIZ
                            );

    Gm = get_BIGINT_from_DAT( 3072
                             ,"../saved_nums/saved_Gm.dat\0"
                             ,3071
                             ,MAX_BIGINT_SIZ
                            );
   
    a  = get_BIGINT_from_DAT( 320
                             ,"../bin/server_privkey.dat\0"
                             ,318
                             ,MAX_BIGINT_SIZ
                            );

    Am = get_BIGINT_from_DAT( 3072
                             ,"../bin/server_pubkeymont.dat\0" 
                             ,3071
                             ,MAX_BIGINT_SIZ
                            );
             
    printf("Result of compare(G, a) : %u\n\n", bigint_compare2(G, a));

    printf("Generating signatures...\n\n");
    
    for(uint64_t i = 0; i < 20; ++i){
        time = clock();
        
        Signature_GENERATE(M, Q, Gm, msg, data_len, result_signature, a, 40);
        
        time = clock() - time;
        total_time_sec = ((double)time)/CLOCKS_PER_SEC;
        printf("Time taken for Sig[%lu]: %lf sec.\n\n", i, total_time_sec);
    }
    
    printf("\nFinished the signatures!\n\n");
 
    s = (struct bigint *)(result_signature + 0);
    e = (struct bigint *)(result_signature + sizeof(struct bigint) + 40);    
    
    s->bits = calloc(1, (size_t)(s->size_bits / 8));
    e->bits = calloc(1, (size_t)(e->size_bits / 8));
 
    memcpy(s->bits, result_signature + (1*sizeof(struct bigint)) +  0, 40);
    memcpy(e->bits, result_signature + (2*sizeof(struct bigint)) + 40, 40);
    
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
    
    isValid = Signature_VALIDATE(Gm, Am, M, Q, s, e, msg, data_len);
    
    if( ! isValid ){
        printf("Valid Signature: NO\n");
    }
    else{
        printf("Valid Signature: YES\n");
    }
    
    return 0; 
}
