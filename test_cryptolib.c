#include "cryptolib.h"

void uint32_print_bits(uint32_t n){
    printf("\n****** Printing bits of uint32 N = %u ******\n", n);
    for(uint8_t i = 0; i < 32; ++i){
        if(n & ( 1 << (31-i) )){
            printf("1");    
        }
        else{
            printf("0");
        }
        if( i==7 || i==15 || i==23 || i==31 ){
            printf(" ");
        }
    }
    printf("\n\n");
}

int main(){

    /* Test the bitwise rolling */
    
    /*
    
    uint32_t T1 = pow(2, 31);
    uint32_t roll_amount = 4;
    
    printf("T1 before left roll: %u\n", T1);
    uint32_print_bits(T1);
    
    uint32_roll_left(&T1, roll_amount);
    
    printf("T1 after left roll : %u\nThe left-rolled bits by %u are:\n", T1, roll_amount);
    uint32_print_bits(T1);

    T1 = 1487532411;
    roll_amount = 10;

    printf("T1 before left roll: %u\n", T1);
    uint32_print_bits(T1);

    uint32_roll_left(&T1, roll_amount);
    
    printf("T1 after left roll : %u\nThe left-rolled bits by %u are:\n", T1, roll_amount);
    uint32_print_bits(T1);
    
    
    */
    
    
    /* Test ChaCha20 */
    
    
    /*
    char* plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you"
                      " only one tip for the future, sunscreen would be it.\0"
                      ;
                      
    uint32_t msg_len = strlen(plaintext);
                      
    uint32_t* key = malloc(8 * sizeof(uint32_t));
    uint8_t key_len = 8;
    key[0] = 0x00010203;
    key[1] = 0x04050607;
    key[2] = 0x08090a0b;
    key[3] = 0x0c0d0e0f;
    key[4] = 0x10111213;
    key[5] = 0x14151617;
    key[6] = 0x18191a1b;
    key[7] = 0x1c1d1e1f;
    
    uint32_t* nonce = malloc(3 * sizeof(uint32_t));
    uint8_t nonce_len = 3;
    nonce[0] = 0x00000000;
    nonce[1] = 0x0000004a;
    nonce[2] = 0x00000000;
    
    char* cyphertext = malloc(msg_len * sizeof(char));
    memset(cyphertext, 0x00, msg_len * sizeof(char));
    
    CHACHA20(plaintext, msg_len, nonce, nonce_len, key, key_len, cyphertext);
    
    printf("THE CYPHERTEXT FROM CHACHA:\n");
    
    for(uint32_t i = 0; i < msg_len; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)cyphertext[i]);

    }
    printf("\n");
    
    printf("\n\n**** NOW TESTING BLAKE2b ****\n\n");
    
    */
    
    
    
    /* Prepare message to be processed by BLAKE2b. */
    
    
    /*
    char *b2b_raw_msg = "abc\0",
         *b2b_out_buf = malloc(65 * sizeof(char));
         
    memset(b2b_out_buf, 0x00, 65*sizeof(char));
    
    
    uint64_t b2b_ll = strlen(b2b_raw_msg)
            ,b2b_kk = 0
            ,b2b_nn = 64
            ;
    */   
    /*     
    printf("**** PASSING ARGUMENTS TO BLAKE2B:\n");
    printf("ll = %lu\n", b2b_ll);
    BLAKE2B_INIT(b2b_raw_msg
                ,b2b_ll
                ,b2b_kk
                ,b2b_nn
                ,b2b_out_buf
                );
                
    printf("BLAKE2b produced 64-byte hash:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)b2b_out_buf[i]);
    }
    printf("\n\n");
    */
    
    /**************************************************************************/
    /********************   NOW TESTING ARGON2id  *****************************/
    /**************************************************************************/
    /*   
    struct Argon2_parms prms;
    
    prms.p = 4;   
    prms.T = 32;  
    prms.m = 32;  
    prms.t = 3;  
    prms.v = 19;  
    prms.y = 2;  
    
    char *P = malloc(32),
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
    
    char* argon2_output_tag = malloc(prms.T);
    
    Argon2_MAIN(&prms, argon2_output_tag);
    
    printf("\n\n***** ARGON2id produced %lu-byte Tag: ******\n\n", prms.T);
    
    for(uint32_t i = 0; i < 32; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)argon2_output_tag[i]);
    }
    printf("\n\n");
    
    */
    
    
    /**************************************************************************/
    /*              NOW TESTING SCHNORR SIGNATURE GENERATOR                   */
    /**************************************************************************/

    struct bigint *M, *Q, *G;
  
    get_M_Q_G(&M, &Q, &G);
    
    uint64_t data_len = 197;
 
    char* msg = malloc(data_len);

    memset(msg, 65, data_len); /* 197 AAAAAAA's. */

    /* ( (2 * sizeof(struct bigint)) + (2 * bytewidth(Q)) )              */
    /* Cuz the signature itself is (s,e) both of which are BigInts whose */
    /* bitwidth is up to the bitwidth of Q and no more.                  */
    char* result_signature = malloc((2 * sizeof(struct bigint)) + (2 * 40));

    /* Assume this private key got generated with 39 bytes. */
    struct bigint priv_key;

    bigint_create(&priv_key, M->size_bits, 0);

    FILE* rand_file = fopen("/dev/urandom", "r");

    if (  (fread(priv_key.bits, 1, 39, rand_file)) == 0  ){
        printf("[ERR] Test Cryptolib - Couldn't read from /dev/urandom.\n");
        if(rand_file){
            fclose(rand_file);
        }
        exit(1);
    }
    /* Make sure the most significant bit is set, so we can really claim
     * that used bits are 39 * 8. 
     */

    *(priv_key.bits + 38) |= ( ((uint8_t)1) << 7 );

    priv_key.used_bits = 39 * 8;

    priv_key.free_bits = priv_key.size_bits - priv_key.used_bits;

    printf("Calling Signature_GENERATE() NOW!!!\n");
    
    Signature_GENERATE(M, Q, G, msg, data_len, result_signature, &priv_key, 39);
                       
    printf("FINISHED SIGNATURE!!\n");
    printf("The resulting signature itself is (s,e) both BigInts.\n");
    printf("But we have to point the .bits pointer to their returned buffer\n");
    
    struct bigint *s = (struct bigint *)(result_signature + 0);
    struct bigint *e = (struct bigint *)(result_signature + sizeof(struct bigint) + 40);    
    
    s->bits = calloc(1, (size_t)(s->size_bits / 8));
    e->bits = calloc(1, (size_t)(e->size_bits / 8));
 
    memcpy(s->bits, result_signature + (1*sizeof(struct bigint)) +  0, 40);
    memcpy(e->bits, result_signature + (2*sizeof(struct bigint)) + 40, 40);
    
    printf("Reconstructed BigInts e and s from what's in Signature.\n");
    printf("\n***** s: *****\n");
    
    bigint_print_info(s);
    bigint_print_bits(s);
    bigint_print_all_bits(s);
    
    printf("\n***** e: *****\n");

    bigint_print_info(e);
    bigint_print_bits(e);
    bigint_print_all_bits(e); 
    
    fclose(rand_file);
    
}









