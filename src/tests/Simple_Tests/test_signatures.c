#include "../../cryptolib.h"

#define RESBITS 12800

int main(){

    /**************************************************************************/
    /*              NOW TESTING SCHNORR SIGNATURE GENERATOR                   */
    /**************************************************************************/



    struct bigint *M, *Q, *G, *Gm, *Am, *a, *s, *e,
      *A_computed = malloc(sizeof(struct bigint));
    
    printf("SIZEOF(STRUCT BIGINT) = %lu\n", sizeof(struct bigint));
    
    bigint_create(A_computed, RESBITS, 0);
    
    uint64_t data_len = 197;
 
    char *msg = malloc(data_len);
    
    
    
        /* ( (2 * sizeof(struct bigint)) + (2 * bytewidth(Q)) )              */
    /* Cuz the signature itself is (s,e) both of which are BigInts whose */
    /* bitwidth is up to the bitwidth of Q and no more.                  */
    
    
    
    char *result_signature = malloc((2 * sizeof(struct bigint)) + (2 * 40));

    M = get_BIGINT_from_DAT( 3072
        ,"../saved_nums/M_raw_bytes.dat\0"
        ,3071
        ,RESBITS
          );
    
    Q = get_BIGINT_from_DAT( 320
        ,"../saved_nums/Q_raw_bytes.dat\0"
        ,320
        ,RESBITS
           );
    G = get_BIGINT_from_DAT( 3072
    ,"../saved_nums/G_raw_bytes.dat\0"
    ,3071
    ,RESBITS
   );

    Gm = get_BIGINT_from_DAT( 3072
    ,"../saved_nums/PRACTICAL_Gmont_raw_bytes.dat\0"
    ,3071
    ,RESBITS
   );
    
    a = get_BIGINT_from_DAT(312
       ,"../saved_nums/testprivkey_raw_bytes.dat\0"
       ,312
       ,RESBITS
      );
      
      
    

    Am = get_BIGINT_from_DAT
   (
    3072
   ,"../saved_nums/PRACTICAL_Amont_raw_bytes.dat\0" 
           ,3072
           ,RESBITS
           );
             

    printf("Result of compare(G, a) : %u\n", bigint_compare2(G, a));

    printf("Calling Signature_GENERATE() NOW!!!\n");
    
    Signature_GENERATE(  M, Q, Gm, (u8*)(msg), data_len
            ,(u8*)(result_signature), a, 39
          );
                  
    printf("FINISHED SIGNATURE!!\n");
    printf("The resulting signature itself is (s,e) both BigInts.\n");
    printf("But we have to point the .bits pointer to their returned buffer\n");
    
    s = (struct bigint *)(result_signature + 0);
    e = (struct bigint *)(result_signature + sizeof(struct bigint) + 40);    
    
    s->bits = calloc(1, (size_t)(s->size_bits / 8));
    e->bits = calloc(1, (size_t)(e->size_bits / 8));
 
    memcpy(s->bits, result_signature + (1*sizeof(struct bigint)) +  0, 40);
    memcpy(e->bits, result_signature + (2*sizeof(struct bigint)) + 40, 40);
    
    printf("Reconstructed BigInts s and e from what's in Signature.\n");
    printf("\n***** s: *****\n");
    
    bigint_print_info(s);
    bigint_print_bits(s);

    
    printf("\n***** e: *****\n");

    bigint_print_info(e);
    bigint_print_bits(e);

    

    /* Compute a public key from the generated private key.   */
    /* This key is used in validating a signature generated from private key. */

    /* A = G^a mod M */
    
    /* We can use montgomery modular MUL mod M function here. */
    /* We already have Gmont above. */

    
    
    
    printf("Ready to call SIGNATURE VALIDATE now!\n");

    uint8_t isValid = 
    Signature_VALIDATE(Gm,Am ,M, Q, s, e, (u8*)(msg), data_len);
    
    printf("FINISHED VALIDATING THE SIGNATURE!\n");
    
    if(!isValid){
    printf("Valid Signature: NO\n");
    }
    else{
    printf("Valid Signature: YES\n");
    }
    
    return 0;
    
    
}
