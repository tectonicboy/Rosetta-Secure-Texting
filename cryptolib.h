#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>

/* Rotation constants for BLAKE2b */
#define R1 32
#define R2 24
#define R3 16
#define R4 63

/* Initialization vector of constants for BLAKE2b */
const uint64_t IV[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

/* Message word permutation constants for BLAKE2b*/
const uint64_t sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

/* Bitwise rolling means shifts but the erased bits go back to the start. */
void uint32_roll_left(uint32_t* n, uint32_t roll_amount){
    uint8_t last_on = 0;
    while(roll_amount > 0){
        last_on = 0;
        if((*n) & ((uint32_t)1 << 31)) { last_on = 1; }
        (*n) <<= 1;
        if(last_on){
            (*n) |= 1;
        }
        --roll_amount;
    }
    return;
}

void uint64_roll_right(uint64_t* n, uint32_t roll_amount){
    uint8_t last_on = 0;
    while(roll_amount > 0){
        last_on = 0;
        if((*n) & ((uint64_t)1)) { last_on = 1; }
        (*n) >>= 1;
        if(last_on){
            (*n) |= ((uint64_t)1 << 63);
        }
        --roll_amount;
    }  
    return; 
}


/*****************************************************************************/
/*                   CHACHA20 IMPLEMENTATION BEGINS                          */
/*****************************************************************************/    

void CHACHA_QROUND(uint32_t* matrix, uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    matrix[a] += matrix[b];
    matrix[d] ^= matrix[a];
    uint32_roll_left((matrix + d), 16);
    
    matrix[c] += matrix[d];
    matrix[b] ^= matrix[c];
    uint32_roll_left((matrix + b), 12);
    
    matrix[a] += matrix[b];
    matrix[d] ^= matrix[a];
    uint32_roll_left((matrix + d), 8);
    
    matrix[c] += matrix[d];
    matrix[b] ^= matrix[c];
    uint32_roll_left((matrix + b), 7); 
    return;
}

void CHACHA_INNER(uint32_t* matrix){
    CHACHA_QROUND(matrix, 0, 4, 8,  12);
    CHACHA_QROUND(matrix, 1, 5, 9,  13);
    CHACHA_QROUND(matrix, 2, 6, 10, 14);
    CHACHA_QROUND(matrix, 3, 7, 11, 15); 
    
    CHACHA_QROUND(matrix, 0, 5, 10, 15);
    CHACHA_QROUND(matrix, 1, 6, 11, 12);
    CHACHA_QROUND(matrix, 2, 7, 8,  13);
    CHACHA_QROUND(matrix, 3, 4, 9,  14);
    return;
}


/*  Part of the block function is to construct the actual 
 *  chacha state matrix. It always consists of exactly
 *  16 unsigned 32-bit numbers. The constants are always
 *  four and always exactly the same as per the spec.
 *  
 *  This means: (key_len + counter_len + nonce_len) 
 *              MUST add up to 12. One unit of length
 *              here means one unsigned 32-bit integer.
 */
void CHACHA_BLOCK_FUNC(uint32_t* key,     uint8_t key_len
                      ,uint32_t* counter, uint8_t counter_len
                      ,uint32_t* nonce,   uint8_t nonce_len
                      ,uint32_t* serialized_result
                 )
{
    if(key_len + counter_len + nonce_len != 12){
        printf("[ERR] Cryptolib - lengths of key, counter, nonce DOES NOT add up to 12.\n");
        return;
    }
    
    uint32_t state[16], initial_state[16], next_ix = 0, i, j;
    
    /* The 4 constants. */               
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32; 
    state[3] = 0x6b206574;
    
    next_ix = 4;
    
    for(i = key_len; i > 0; --i){
        for(j = 0; j < 4; ++j){
            *(((uint8_t*)(&(state[next_ix]))) + (3-j)) = *(((uint8_t*)(&(key[key_len - i]))) + j);
        }
        ++next_ix;
    }           
    if(counter_len){
        state[next_ix] = *counter;
        ++next_ix;
    }  
    for(i = nonce_len; i > 0; --i){
        for(j = 0; j < 4; ++j){
            *(((uint8_t*)(&(state[next_ix])))+(3-j)) = *(((uint8_t*)(&(nonce[nonce_len - i])))+j);
        }
        ++next_ix;
    }      
    
    memcpy((void*)initial_state, (void*)state, 16 * sizeof(uint32_t));
    
    printf("\nCONSTRUCTED CHACHA STATE MATRIX:\n");
    printf("%08X\t%08X\t%08X\t%08X\n", state[0], state[1], state[2], state[3]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[4], state[5], state[6], state[7]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[8], state[9], state[10], state[11]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[12], state[13], state[14], state[15]);
    
        
    for(i = 1; i <= 10; ++i){
        CHACHA_INNER(state);
    }
    
    for(i = 0; i < 16; ++i){
        state[i] += initial_state[i];
    }
    
    printf("\nRESULTING CHACHA STATE MATRIX:\n");
    printf("%08X\t%08X\t%08X\t%08X\n", state[0], state[1], state[2], state[3]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[4], state[5], state[6], state[7]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[8], state[9], state[10], state[11]);
    printf("%08X\t%08X\t%08X\t%08X\n", state[12], state[13], state[14], state[15]);
    
    /* Every uint32_t has its bytes reversed. This is the serialized result. */
    /* So each uint32_t goes:                                                */
    /* from [byte_0 byte_1 byte_2 byte_3] to [byte_3 byte_2 byte_1 byte_0]   */
    for(i = 0; i < 16; ++i){
        for(j = 0; j < 4; ++j){
            *(((uint8_t*)(&(serialized_result[i]))) + j) = *(((uint8_t*)(&(state[i]))) + j);
        }     
    }
    return;
}

void CHACHA20(char* plaintext, uint32_t txt_len
             ,uint32_t* nonce, uint8_t nonce_len
             ,uint32_t* key,   uint8_t key_len 
             ,char* cyphertext
             )
{
    /* This sum can be either 16 or 15. 16 means no space for Counter,
     * 15 means one uint32 space for counter. 64-bit counters or bigger are unsupported.
     */
    if(key_len + nonce_len + 4 > 16 || key_len + nonce_len + 4 < 15){
        printf("[ERR] Cryptolib - sum of lengths of key, nonce, constants is invalid.\n");
        return;
    }

    uint32_t num_matrices = (uint32_t)ceil((double)txt_len / 64.0)
             , i, j, counter_len = 16 - (key_len + nonce_len + 4)
            ,last_txt_block_len = (txt_len % 64)
            ;
            
    uint32_t** outputs = malloc(num_matrices * sizeof(uint32_t*));
    
    for(i = 0; i < num_matrices; ++i){
        outputs[i] = malloc(64 * sizeof(char));   
    }

    uint32_t* counter = NULL;
    
    if(counter_len > 0){
        counter = malloc(sizeof(uint32_t));
        *counter = 1;
    }
    
    printf("Required number of chacha matrices: %u, with txt_len: %u\n", num_matrices, txt_len);
    for(i = 0; i < num_matrices; ++i){
        CHACHA_BLOCK_FUNC(key, key_len, counter, counter_len, nonce, nonce_len, outputs[i]);
        if(counter){ ++(*counter); } 
    }
    
    
    uint32_t bytes_printed = 0;
    printf("\nGenerated ChaCha KEYSTREAM:\n");
    for(i = 0; i < num_matrices; ++i){
        for(j = 0; j < 64; ++j){
            printf("%02X:", ((uint8_t*)(outputs[i]))[j]);
            ++bytes_printed;
            if(bytes_printed % 23 == 0 && bytes_printed > 0){ printf("\n"); }
        }
    }
    printf("\n\n");
    
    uint32_t full_txt_blocks = 0;
    if(num_matrices == 1 && last_txt_block_len == 0){
        full_txt_blocks = 1;
    }
    else{
        full_txt_blocks = num_matrices - 1;
    }
    
    for(i = 0; i < full_txt_blocks; ++i){
        for(j = 0; j < 64; ++j){
            cyphertext[(64*i) + j] 
            =   plaintext[(64*i) + j] 
                ^ 
                ((uint8_t*)(outputs[i]))[j]
            ;
        }      
    }
    
    if(last_txt_block_len){
        for(j = 0; j < last_txt_block_len; ++j){
            cyphertext[(64*full_txt_blocks) + j] 
            =   plaintext[(64*full_txt_blocks) + j] 
                ^ 
                ((uint8_t*)(outputs[full_txt_blocks]))[j]
            ;
        }            
    }
    
    /* Cleanup */
    if(counter){free(counter);}
    for(i = 0; i < num_matrices; ++i){
        free(outputs[i]);   
    }
    free(outputs);
    return;
}

void BLAKE2B_G(uint64_t* v, uint64_t a, uint64_t b, uint64_t c
              ,uint64_t  d, uint64_t x, uint64_t y
              )
{
    v[a] = v[a] + v[b] + x;
    v[d] ^= v[a];
    uint64_roll_right(&(v[d]), R1);
    
    v[c] += v[d];
    v[b] ^= v[c];
    uint64_roll_right(&(v[b]), R2);
    
    v[a] = v[a] + v[b] + y;
    v[d] ^= v[a];
    uint64_roll_right(&(v[d]), R3);
    
    v[c] += v[d];
    v[b] ^= v[c];
    uint64_roll_right(&(v[b]), R4); 
    return;
}    
    
void BLAKE2B_F(uint64_t* h, uint64_t* m, uint64_t t, uint8_t f){
    uint64_t v[16];
    memcpy(v, h,  8*sizeof(uint64_t));
    memcpy(v + 8, IV, 8*sizeof(uint64_t));
    
    
    
    /* NOTE: Usually, t is a 128-bit unsigned integer. The second
     *       64 bits are used if the input message has more than 
     *       0xFFFFFFFFFFFFFFFF bytes in it, which is never gonna
     *       happen in my secure chat app. So hardcode v[13] which
     *       is supposed to store said second 64 bits of t to 0.
     */
     printf("Changing v[12] now. XORing it with (HEX) t = %lx\n", t);
     
    v[12] ^= t;
    v[13] ^= 0;

    if(f){ v[14] = ~v[14]; }
    
    uint64_t s[16];
    
    printf("\n\n***** BEFORE Entering the 12 for-loop. v = \n\n");

        for(uint64_t x = 0; x < 16; ++x){
            printf("v[%lu] (HEX)\t= %lX\nv[%lu] (DEC)\t= %lu\n\n", x, v[x], x, v[x]);    
        } printf("\n\n");
    
    printf("NOW ENTERING the 12 for-loop... It prints v[] at every run.\n\n");
    
    for(uint8_t i = 0; i < 12; ++i){
        memcpy(s, (sigma[i % 12]), (16*sizeof(uint64_t)));
     
             printf("(i = %u) v[16] = \n", i);
        for(uint64_t x = 0; x < 16; ++x){
            printf("v[%lu]\t=\t%lX\n", x, v[x]);    
        } printf("\n\n");
     
        BLAKE2B_G(v, 0, 4, 8,  12, m[s[0]], m[s[1]]);
        BLAKE2B_G(v, 1, 5, 9,  13, m[s[2]], m[s[3]]);
        BLAKE2B_G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        BLAKE2B_G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        
        BLAKE2B_G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        BLAKE2B_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        BLAKE2B_G(v, 2, 7, 8,  13, m[s[12]], m[s[13]]);
        BLAKE2B_G(v, 3, 4, 9,  14, m[s[14]], m[s[15]]);
    }   
    for(uint8_t i = 0; i < 8; ++i){
        h[i] ^= (v[i] ^ v[i+8]);
    }
    return;
}

/* Input 1 - Padded message blocks. It's a 2D array. 
 *           Each element is a 1D array of exactly 16 uint64_t's.
 *           
 * Input 2 - Input bytes. Must be in [0, 2^128). 
 * Input 3 - Key bytes. Must be in [0, 64].
 * Input 4 - Hash bytes (how much output we want). Must be in [1, 64].
 */
void BLAKE2B(uint64_t** d, uint64_t ll, uint64_t kk, 
             uint64_t  dd, uint64_t nn, char* ret_bytes
            )
{
    uint64_t h[8];
    
    printf("\n B2B Unkeyed Data blocks:\n");
    for(uint64_t i = 0; i < dd; ++i){
        for(uint64_t j = 0; j < 16; ++j){
            if(j % 3 == 0 && j > 0){ printf("\n"); }
            printf("%16lX ", d[i][j]);
        }
    } printf("\n");
    
    memcpy(h, IV, 8*sizeof(uint64_t));
    printf("h[0..8] POPULATED. Now changing h[0] where v[0] comes from.");
    printf("BEFORE THE ERRONEOUS v[0], the calculation operands in HEX:\n");
    printf("h[0]\t\t\t^=\t0x01010000\t^\t(kk\t<<\t8)\t^\tnn = \n");
    printf("%lX\t^=\t0x01010000\t^\t(%lX\t<<\t8)\t^\t%lX\n", h[0], kk, nn);
    
    h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;
    
    printf("\nTHIS GAVE THE HEX RESULT: h[0] = v[0] = %lX\n\n", h[0]);
    
    printf("BEFORE CALLING F(), ll = %lu (decimal). We pass(ll+128) to F().\n\n", ll);
    
    /* Process padded key and data blocks. */
    if(dd > 1){
        for(uint64_t i = 0; i < (dd-1); ++i){
            BLAKE2B_F(h, (d[i]), (i+1)*128, 0);
        }
    }
    /* Final block. */
    if(kk == 0){ BLAKE2B_F(h, d[dd-1], ll, 1); }
    else       { BLAKE2B_F(h, d[dd-1], ll + 128, 1); }
    /* Return the first NN bytes of the resulting little-endian word array h. 
     * The BLAKE2B initializer function must provide this buffer with enough 
     * memory allocated to hold NN bytes.
     */
    memcpy(ret_bytes, h, nn);
    return;
}
        
/* Prepare padded 2D array of key and message blocks d.
 * Prepare the buffer which will hold the result of BLAKE2B
 * with enough allocated memory to hold NN bytes.  
 *
 * This function is the one that will be called by whoever
 * wants to use BLAKE2B in the first place. 
 *
 * NOTE: In the security scheme of my secure chat app, all uses
 *       of BLAKE2B are without a key, kk=0. So I will hardcode
 *       kk=0 for now because it gets complicated with it and
 *       the RFC reference implementation differs from the 
 *       provided pseudocode in the same document, which I'm
 *       following in order to implement this algorithm.
 *
 * The caller must provide:
 * m  - the raw message input.
 * ll - length in bytes of the input message
 * kk - length of secret key. Never used here, so always passed as 0.
 * nn - How many bytes of output we want from BLAKE2B.
 * rr - result buffer for BLAKE2B's output. Must have been already allocated.
 */      
void BLAKE2B_INIT(char* m, uint64_t ll, uint64_t kk, uint64_t nn, char* rr){

    /* Hardcoded to 0 for now, as no current use of BLAKE2B uses a key input. */
    kk = 0;
    
    /* Find how many data blocks we will need in the 2D array d */
    uint64_t dd = ceil((double)kk/128.0) + ceil((double)ll/128.0);
    
    /* Find length of last data block */
    uint64_t last_len = ll % 128;
    
    uint64_t** data_blocks = malloc(dd * sizeof(uint64_t*));
    
    for(uint64_t i = 0; i < dd; ++i){
        data_blocks[i] = malloc(16 * sizeof(uint64_t));
        memset(data_blocks[i], 0x00, 16*sizeof(uint64_t));
        /* at last block? */
        if(i == dd-1){
            /* if it's 0, that means last block's length is 128. */
            if(last_len == 0){ last_len = 128; }
            memcpy(data_blocks[i], m + ((dd-1) * 128), last_len); 
            break;
        }
        /* All blocks before last one are always full 128 bytes. */
        else{
            memcpy(data_blocks[i], m + (i*128), 128);
        }
    }
    BLAKE2B(data_blocks, ll, kk, dd, nn, rr);
    
    for(uint64_t i = 0; i < dd; ++i){
        free(data_blocks[i]);
    }
    free(data_blocks);
    return;
}
    
/*****************************************************************************/
/*                    ARGON2 IMPLEMENTATION BEGINS                           */
/*****************************************************************************/

/* NOTE: The arithmetic operations here are done modulo 2^64. 
 *       Since we're working with uint64_t's, this simply
 *       means we can let overflow happen and ignore it. 
 */
void Argon2_GB(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d){

    (*a) = (*a) + (*b) 
           +    /* Take only the 32 least significant bits of a and b. */ 
           (2 * ((uint64_t)(*((uint32_t*)a))) * ((uint64_t)(*((uint32_t*)b))));

    (*d) = ((*d) ^ (*a));
    uint64_roll_right(d, 32);
    
    (*c) = (*c) + (*d) 
           + 
           (2 * ((uint64_t)(*((uint32_t*)c))) * ((uint64_t)(*((uint32_t*)d))));
    
    (*b) = ((*b) ^ (*c));
    uint64_roll_right(b, 24);
    
    (*a) = (*a) + (*b) 
           + 
           (2 * ((uint64_t)(*((uint32_t*)a))) * ((uint64_t)(*((uint32_t*)b))));
            
    (*d) = ((*d) ^ (*a));
    uint64_roll_right(d, 16);
    
    (*c) = (*c) + (*d) 
           +   
           (2 * ((uint64_t)(*((uint32_t*)c))) * ((uint64_t)(*((uint32_t*)d))));
          
    (*b) = ((*b) ^ (*c));
    uint64_roll_right(b, 63);
    
    return;
}
    
/* Takes eight 16-byte inputs and constructs a 2D array of 4x4 uint64_t's.  
 * Input is in the form of a 128-byte contiguous memory block.
 * It comes from rows or columns of the 2D array of 8x8 16-byte numbers
 * that was constructed in Argon2's G() from its 1024-byte input. 
 *
 * NOTE: 2D arrays[][] are simply contiguos 1D arrays in memory, where
 *       the next row starts right beside the previous row, literally
 *       the immediate memory address. We can use this in our implementation
 *       by utilizing careful pointer programming. 
 */
void Argon2_P(char* input_128){
 
    /* To make the calls to GB() more elegant, prepare
     * the matrix of 4x4 uint64_t's in advance.
     */
    uint64_t** matrix = malloc(16 * sizeof(uint64_t*));
    
    for(size_t i = 0; i < 15; ++i){
        matrix[i] = (uint64_t*)(input_128 + (i*8));
    }
    
    Argon2_GB(matrix[0], matrix[4], matrix[8],  matrix[12]);
    Argon2_GB(matrix[1], matrix[5], matrix[9],  matrix[13]);
    Argon2_GB(matrix[2], matrix[6], matrix[10], matrix[14]);
    Argon2_GB(matrix[3], matrix[7], matrix[11], matrix[15]);
    
    Argon2_GB(matrix[0], matrix[5], matrix[10], matrix[15]);
    Argon2_GB(matrix[1], matrix[6], matrix[11], matrix[12]);
    Argon2_GB(matrix[2], matrix[7], matrix[8],  matrix[13]);
    Argon2_GB(matrix[3], matrix[4], matrix[9],  matrix[14]);

    free(matrix);
    return;
}

/* Compression function G() for Argon2. 
 * Takes two 1024-byte blocks as input (X, Y).
 * Outputs one resulting 1024-byte block.
 *
 * Pass a pointer to where the output 1024-byte block is.
 *
 * Does not change the input memory blocks X and Y directly.
 */
void Argon2_G(char* X, char* Y, char* out_1024){
    char* matrix_R = malloc(1024);
    
    size_t i, j;
    
    for(i = 0; i < 1024; ++i){
        matrix_R[i] = X[i] ^ Y[i];   
    }    

    /*  R is used at the end, so save it. Pass a copy of it to P() 
     *  which itself will be transformed twice by P(), first into
     *  matrix Q, then Q into matrix Z.
     */
    
    char* R_transformed = malloc(1024);
    
    memcpy(R_transformed, matrix_R, 1024);
    
    /*  Use P() to transform matrix R into matrix Q.     
     *  Each ROW of matrix R is fed as the input to P(), 
     *  producing the respective rows of matrix Q.
     */
    for(i = 0; i < 8; ++i){
        Argon2_P(R_transformed + (i * 128));    
    }
    
    /*  Now further transform matrix Q into matrix Z.   
     *  Each COLUMN of matrix Q is fed as input to P(), 
     *  producing the respective columns of matrix Z.
     *
     *  Since columns are not contiguous in memory, we 
     *  form new 128-byte buffers to serve as the 128-byte
     *  contiguous memory block input to transformation P(),
     *  the transformed output buffers we will use to construct 
     *  matrix Z at the end.
     */
    char* Q_columns = malloc(1024);
    
    for(i = 0; i < 8; ++i){ /* for each of the 8 rows in Q */
        for(j = 0; j < 8; ++j){ /* for each 16-byte register in that row */
            memcpy(
                   Q_columns     + (j * 128) + (i * 16)
                  ,R_transformed + (i * 128) + (j * 16)
                  ,16
                  );
        }                    
    }   
    
    /* Now that we have the columns of Q in eight contiguous 128-byte byffers,
     * we are ready to feed them in P() transformation.
     */
    for(i = 0; i < 8; ++i){
        Argon2_P(Q_columns + (i * 128));    
    }   
    
    char* matrix_Z = malloc(1024);
    
    /* Reconstruct the contiguous rows of Z. This is the final matrix. */
    for(i = 0; i < 8; ++i){ /* for each column of matrix Q */
        for(j = 0; j < 8; ++j){ /* for each 16-byte register in that column */
            memcpy(
                   matrix_Z  + (j * 128) + (i * 16)
                  ,Q_columns + (i * 128) + (j * 16)
                  ,16
                  );
        }                    
    }   
    
    /* Final output is (R XOR Z). */
    for(i = 0; i < 1024; ++i){
        out_1024[i] = matrix_R[i] ^ matrix_Z[i];
    }

    free(matrix_R);
    free(matrix_Z);
    free(R_transformed);
    free(Q_columns);
    return;
}
    
    
    
    
    
    
    
                 

