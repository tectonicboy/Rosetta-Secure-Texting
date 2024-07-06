#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <immintrin.h> /* for _mulx_u64      */
#include <adxintrin.h> /* for _addcarryx_u64 */
#include "bigint.h"

#include <time.h> /* for performance testing only. */
double cpu_time_used1, cpu_time_used2, cpu_time_used_total;

/* mutex for testing only so we can see prints in argon2's G() properly */
pthread_mutex_t lock;

/* Rotation constants for BLAKE2b */
#define R1 32
#define R2 24
#define R3 16
#define R4 63

/* Montgomery Modular Multiplication constants. */
#define MONT_LIMB_SIZ 8  /* Size in bytes of limbs in Montgomery numbers.    */
#define MONT_L        48 /* Non-zero-padded number of limbs in DH modulus M. */
#define MONT_MU       5519087143809977509 /* Multiplicative inverse */

/* Simplifies pointer arithmetic for access to Argon2's memory matrix B. */
typedef struct block{
    uint8_t block_data[1024];
} block_t;

typedef struct block_64{
    uint8_t block_data[64]; 
} block64_t;
        
/* Parameters of Argon2
 * 
 * Every user of Argon2 should initialize an instance of this structure
 * and pass it to Argon2_MAIN(), which will, on its own, initialize
 * H_0 based on fields of this struct, and proceed with Argon2 operation.
 */
struct Argon2_parms{
    uint64_t p;  /* Paralellism - how many threads to use. 1   to (2^24) - 1 */
    uint64_t T;  /* Output Tag's desired length in bytes.  4   to (2^32) - 1 */
    uint64_t m;  /* Memory usage - kikibytes to use.       8*p to (2^32) - 1 */
    uint64_t t;  /* Number of passes Argon2 should do.     1   to (2^32) - 1 */
    uint64_t v;  /* Version number.                        It is always 0x13 */
    uint64_t y;  /* Type of Argon2 algorithm.              0x02 for Argon2id */ 
    
    uint8_t* P;  /* Password plaintext to hash. */
    uint8_t* S;  /* Salt.                       */
    uint8_t* K;  /* OPTIONAL secret value.      */
    uint8_t* X;  /* OPTIONAL associated data.   */
    
    uint64_t len_P; /* Length of password plaintext in bytes. <= (2^32) - 1  */
    uint64_t len_S; /* Length of Salt in bytes.               <= (2^32) - 1  */                    
    uint64_t len_K; /* Length of secret value in bytes.       <= (2^32) - 1  */
    uint64_t len_X; /* Length of associated data in bytes.    <= (2^32) - 1  */   
}; 

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

/* Useful offsets into the input buffer for the thread function of Argon2. */
#define OFFSET_r  (sizeof(block_t*) + (0 * sizeof(uint64_t)))
#define OFFSET_l  (sizeof(block_t*) + (1 * sizeof(uint64_t)))
#define OFFSET_sl (sizeof(block_t*) + (2 * sizeof(uint64_t)))
#define OFFSET_md (sizeof(block_t*) + (3 * sizeof(uint64_t)))
#define OFFSET_t  (sizeof(block_t*) + (4 * sizeof(uint64_t)))
#define OFFSET_y  (sizeof(block_t*) + (5 * sizeof(uint64_t)))
#define OFFSET_p  (sizeof(block_t*) + (6 * sizeof(uint64_t)))
#define OFFSET_q  (sizeof(block_t*) + (7 * sizeof(uint64_t)))

/* Bitwise rolling means shifts but the erased bits go back to the start. */
void uint32_roll_left(uint32_t* n, uint32_t roll_amount){
    uint8_t last_on = 0;
    while(roll_amount > 0){
        last_on = 0;
        if((*n) & ((uint32_t)1 << 31)) {
            last_on = 1; 
        }
        (*n) <<= 1;
        if(last_on){
            (*n) |= 1;
        }
        --roll_amount;
    }
    return;
}
/*
void uint64_roll_right(uint64_t* n, uint32_t roll_amount){
    uint8_t last_on = 0;
    while(roll_amount > 0){
        last_on = 0;
        if((*n) & ((uint64_t)1)) { 
            last_on = 1; 
        }
        (*n) >>= 1;
        if(last_on){
            (*n) |= ((uint64_t)1 << 63);
        }
        --roll_amount;
    }  
    return; 
}
*/
//#define uint64_roll_right(v,n) ( (*((v)))  >>(n)|(*((v)))<<(64-(n)))

__attribute__ ((always_inline)) 
inline
void uint64_roll_right(uint64_t* n, uint32_t roll_amount){
	*n = *n>>roll_amount | *n<<(64-roll_amount);
}

/*****************************************************************************/
/*                   CHACHA20 IMPLEMENTATION BEGINS                          */
/*                                                                           */
/*     The implementation is based on RFC 8439's theoretical description.    */
/*****************************************************************************/    

void CHACHA_QROUND(uint32_t* matrix, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
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
        printf("[ERR] Cryptolib - lengths of key, counter,"
               " nonce DOES NOT add up to 12.\n");
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
            *(((uint8_t*)(&(state[next_ix]))) + (3-j)) 
              = *(((uint8_t*)(&(key[key_len - i]))) + j);
        }
        ++next_ix;
    }           
    if(counter_len){
        state[next_ix] = *counter;
        ++next_ix;
    }  
    for(i = nonce_len; i > 0; --i){
        for(j = 0; j < 4; ++j){
            *(((uint8_t*)(&(state[next_ix])))+(3-j)) 
              = *(((uint8_t*)(&(nonce[nonce_len - i])))+j);
        }
        ++next_ix;
    }      
    
    memcpy((void*)initial_state, (void*)state, 16 * sizeof(uint32_t));

    for(i = 1; i <= 10; ++i){
        CHACHA_INNER(state);
    }
    
    for(i = 0; i < 16; ++i){
        state[i] += initial_state[i];
    }

    /* Every uint32_t has its bytes reversed. This is the serialized result. */
    /* So each uint32_t goes:                                                */
    /* from [byte_0 byte_1 byte_2 byte_3] to [byte_3 byte_2 byte_1 byte_0]   */
    for(i = 0; i < 16; ++i){
        for(j = 0; j < 4; ++j){
            *(((uint8_t*)(&(serialized_result[i]))) + j) 
              = *(((uint8_t*)(&(state[i]))) + j);
        }     
    }
    return;
}

void CHACHA20(uint8_t* plaintext, uint32_t txt_len
             ,uint32_t* nonce, uint8_t nonce_len
             ,uint32_t* key,   uint8_t key_len 
             ,uint8_t* cyphertext
             )
{
    /* This sum can be either 16 or 15. 16 means no space for Counter,
     * 15 means one uint32 space for counter. 
     * 64-bit counters or bigger are unsupported.
     */
    if(key_len + nonce_len + 4 > 16 || key_len + nonce_len + 4 < 15){
        printf("[ERR] Cryptolib - sum of lengths of key,"
               " nonce, constants is invalid.\n");
        return;
    }

    uint32_t num_matrices = (uint32_t)ceil((double)txt_len / 64.0)
             , i, j, counter_len = 16 - (key_len + nonce_len + 4)
            ,last_txt_block_len = (txt_len % 64)
            ;
            pthread_mutex_unlock(&lock); 
    uint32_t** outputs = malloc(num_matrices * sizeof(uint32_t*));
    
    for(i = 0; i < num_matrices; ++i){
        outputs[i] = malloc(64 * sizeof(uint8_t));   
    }

    uint32_t* counter = NULL;
    
    if(counter_len > 0){
        counter = malloc(sizeof(uint32_t));
        *counter = 1;
    }

    for(i = 0; i < num_matrices; ++i){
    
        CHACHA_BLOCK_FUNC(key, key_len, counter, counter_len, 
                          nonce, nonce_len, outputs[i]
                         );      
        if(counter){ 
            ++(*counter); 
        } 
    }

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

/*****************************************************************************/
/*                   BLAKE2B IMPLEMENTATION BEGINS                           */
/*                                                                           */
/*     The implementation is based on RFC 7693's theoretical description.    */
/*****************************************************************************/  

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
    /* printf("Changing v[12] now. XORing it with (HEX) t = %lx\n", t);*/
     
    v[12] ^= t;
    v[13] ^= 0;

    if(f){ v[14] = ~v[14]; }
    
    uint64_t s[16];
    
   
    for(uint8_t i = 0; i < 12; ++i){
        memcpy(s, (sigma[i % 12]), (16*sizeof(uint64_t)));

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
             uint64_t  dd, uint64_t nn, uint8_t* ret_bytes
            )
{
    uint64_t h[8];

    memcpy(h, IV, 8*sizeof(uint64_t));

    h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;

    /* Process padded key and data blocks. */
    if(dd > 1){
        for(uint64_t i = 0; i < (dd-1); ++i){
            BLAKE2B_F(h, (d[i]), (i+1)*128, 0);
        }
    }
    /* Final block. */
    if(kk == 0){ 
        BLAKE2B_F(h, d[dd-1], ll, 1); 
    }
    else{ 
        BLAKE2B_F(h, d[dd-1], ll + 128, 1); 
    }
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
void BLAKE2B_INIT(uint8_t* m, uint64_t ll, uint64_t kk, uint64_t nn, uint8_t* rr){

    /* Hardcoded to 0 for now, as no current use of BLAKE2B is keyed. */
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
            if(last_len == 0){ 
                last_len = 128; 
            }
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
/*                   Argon2id IMPLEMENTATION BEGINS                          */
/*                                                                           */
/*     The implementation is based on RFC 9106's theoretical description.    */
/*****************************************************************************/ 

/* NOTE: The arithmetic operations here are done modulo 2^64. 
 *       Since we're working with uint64_t's, this simply
 *       means we can let overflow happen and ignore it. 
 */
__attribute__ ((always_inline)) 
inline 
void Argon2_GB(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d){
    *a = *a + *b 
          +    /* Take only the 32 least significant bits of a and b. */ 
          ((uint64_t)2 * ((uint64_t)((uint32_t)*a)) * ((uint64_t)((uint32_t)*b)));
           
    *d = *d ^ *a;
    
    uint64_roll_right(d, 32);
    
    *c = *c + *d 
          + 
          ((uint64_t)2 * ((uint64_t)((uint32_t)*c)) * ((uint64_t)((uint32_t)*d)));
           
    *b = *b ^ *c;
    uint64_roll_right(b, 24);
    
    *a = *a + *b 
          + 
          ((uint64_t)2 * ((uint64_t)((uint32_t)*a)) * ((uint64_t)((uint32_t)*b)));   
             
    *d = *d ^ *a;
    uint64_roll_right(d, 16);
    
    *c = *c + *d
          +   
          ((uint64_t)2 * ((uint64_t)((uint32_t)*c)) * ((uint64_t)((uint32_t)*d)));   
           
    *b = *b ^ *c;
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
void Argon2_P(uint8_t* input_128){
 
    /* To make the calls to GB() more elegant, prepare
     * the matrix of 4x4 uint64_t's in advance.
     */
    uint64_t** matrix = malloc(16 * sizeof(uint64_t*));
    
    for(size_t i = 0; i < 16; ++i){
        matrix[i] = (uint64_t*)(input_128 + (i*8));
    }
    Argon2_GB((matrix[0]), (matrix[4]), (matrix[8]),  (matrix[12]));
    Argon2_GB((matrix[1]), (matrix[5]), (matrix[9]),  (matrix[13]));
    Argon2_GB((matrix[2]), (matrix[6]), (matrix[10]), (matrix[14]));
    Argon2_GB((matrix[3]), (matrix[7]), (matrix[11]), (matrix[15]));
    Argon2_GB((matrix[0]), (matrix[5]), (matrix[10]), (matrix[15]));
    Argon2_GB((matrix[1]), (matrix[6]), (matrix[11]), (matrix[12]));
    Argon2_GB((matrix[2]), (matrix[7]), (matrix[8]),  (matrix[13]));
    Argon2_GB((matrix[3]), (matrix[4]), (matrix[9]),  (matrix[14]));

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
__attribute__ ((always_inline)) 
inline
void Argon2_G(uint8_t* X, uint8_t* Y, uint8_t* out_1024){

	/*
	pthread_mutex_lock(&lock); 
	
	printf("TWO INPUT BLOCKS IN G():\n\n");
	printf("X:\n\n");
   	for(uint32_t i = 0; i < 1024; ++i){
		if(i % 16 == 0 && i > 0){printf("\n");}
		printf("%02x ", ( (X)[i] )) ;
	}
	printf("\n\n"); 
	printf("Y:\n\n");
   	for(uint32_t i = 0; i < 1024; ++i){
		if(i % 16 == 0 && i > 0){printf("\n");}
		printf("%02x ", ( (Y)[i] )) ;
	}
	printf("\n\n"); 
	
	pthread_mutex_unlock(&lock); 
	*/

    uint8_t* matrix_R = malloc(1024);
    
    size_t i, j;
    
    for(i = 0; i < 1024; ++i){
        matrix_R[i] = X[i] ^ Y[i]; 
    }    

    /*  R is used at the end, so save it. Pass a copy of it to P() 
     *  which itself will be transformed twice by P(), first into
     *  matrix Q, then Q into matrix Z.
     */
    
    uint8_t* R_transformed = malloc(1024);
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
    uint8_t* Q_columns = malloc(1024);
    
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
    
    uint8_t* matrix_Z = malloc(1024);
    
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
    
void Argon2_H_dash(uint8_t* input,   uint8_t* output
                  ,uint32_t out_len, uint64_t in_len
                  )
{  

	memset(output, 0x00, out_len);
	
    uint8_t*   H_input;
    uint32_t   r;
    block64_t* V;
    
    H_input = malloc(4 + in_len);
    
    memcpy(H_input + 0, &out_len, sizeof(uint32_t)); 
    memcpy(H_input + 4, input,    in_len); 
    
    if(out_len <= 64){ 
    	/*
    	printf("Input parms to Tag-producing BLAKE2B call:\n");
    	printf("H_input:\n");
		for(uint32_t i = 0; i < (4 + in_len); ++i){
		    if(i % 16 == 0 && i > 0){printf("\n");}
		    printf("%02x ", (uint8_t)H_input[i]);
		}
		printf("\n\n");
    	printf("(4 + in_len): %lu\n", (4 + in_len));
    	printf("0:0\n");
    	printf("out_len: %u\n", out_len);
    	printf("output: emptied now.\n\n");
    	*/
        BLAKE2B_INIT(H_input, (4 + in_len), 0, out_len, output);
        return;
    }
    else{
        r = ceil(out_len / 32) - 2;
        
        /* We allocate memory for (r+1) 64-byte V[i]'s.                  
         * We pass a pointer to the next 64-byte memory block V[i] 
         * as the output destination of BLAKE2.
         */
        V = malloc( (r+1) * sizeof(block64_t));
        
        BLAKE2B_INIT(H_input, (4 + in_len), 0, 64, V[0].block_data);
        for(uint64_t i = 1; i <= r-1; ++i){
            BLAKE2B_INIT(V[i-1].block_data, 64, 0, 64, V[i].block_data);  
        }
        
        BLAKE2B_INIT(
                      V[r-1].block_data, 64, 0,
                      (out_len-(32*r)), V[r].block_data
                    );         
        /* Construct a buffer of concatenated W1 || W2 ... || Wr || V_(r+1)  
         * and place this result in the output target buffer of H_dash here. 
         * Note, Wi is the 32 least significant bytes of 64-byte Vi. 
         */ 
        
        /* Output buffer's size must be ((r * 4) + 8) bytes. Preallocated. */
        for(uint64_t i = 0; i <= r-1; ++i){
            memcpy(output + (32*i), V[i].block_data, 32);
        }      
        memcpy(output + (32*r), V[r].block_data, 64);

		
    }

    /*Cleanup*/
    free(H_input);
    free(V);
    return;
}



void argon2_initJ1J2_blockpool_for2i
				(uint8_t* Z, block_t* blocks, uint64_t num_blocks)
{
    /* We are about to compute ( q / (128*SL) ) 1024-byte blocks. SL=4 slices.*/
    /* Allocate memory for them after working out exactly how many to compute */
    uint64_t G_inner_counter = 0;

    /* Some helpers for constructing the input to the usage of G() here. */
    uint8_t *zero1024 = malloc(1024)
           ,*zero968  = malloc(968);
           
    memset(zero1024, 0x00, 1024);
    memset(zero968,  0x00, 968 );
    
    /* Remember, Argon2 G() takes two 1024-byte blocks and outputs one block. */
    
    uint8_t *G_inner_input_2 = malloc(1024), /* 2nd arg. of inner G() call.  */
            *G_inner_output  = malloc(1024), /* outout   of inner G() call,  */
                                             /* which is input to outer G(). */
            *G_outer_output  = malloc(1024); /* Output of outer call to G(). */
            
    /* Initialize the buffer for 2nd input block to inner call of G(). */
    memcpy(G_inner_input_2, Z, 6*sizeof(uint64_t));
           
    memcpy(G_inner_input_2 + (7*sizeof(uint64_t))
          ,zero968
          ,968
          );
          
    /* Generate the 1024-byte blocks. */      
    for(uint64_t i = 0; i < num_blocks; ++i){
    
        /* Increment the counter inside 2nd input to inner G() call. */
        ++G_inner_counter;
        
        memcpy(G_inner_input_2 + (6*sizeof(uint64_t))
              ,&G_inner_counter
              ,sizeof(uint64_t)
              );
    
        /* First do the inner G(), whose output is 2nd input to outer G(). */
        Argon2_G(zero1024, G_inner_input_2, G_inner_output);
        
        /* Now the outer G() that generates this actual 1024-byte block. */
        Argon2_G(zero1024, G_inner_output, (uint8_t*)(&(blocks[i])));  
    }
      
    /*Cleanup*/
    free(zero1024); 
    free(zero968);  
    free(G_inner_input_2); 
    free(G_inner_output);  
    free(G_outer_output); 
    return; 
} 

uint64_t Argon2_getLZ(uint64_t r, uint64_t sl, uint64_t cur_lane, uint64_t p, 
                     uint32_t J_1, uint32_t J_2, uint64_t n, uint64_t q, 
                     uint64_t computed_blocks)
{
    uint64_t W_siz, *W, W_ix, x, y, zz, l_ix, z_ix;
    size_t old_slice;

    /* Generate index l_ix. */
    if(r == 0 && sl == 0){
        l_ix = cur_lane;
    }
    else{
        l_ix = J_2 % p;
    }     
    /* Compute the size of, allocate and populate index array W[]. */
    W_ix = 0;
    if(l_ix != cur_lane){
        W_siz = sl * n; 

        W = malloc(W_siz * sizeof(size_t));
        
        for(old_slice = 0; old_slice < sl; ++old_slice){
        
            for(  size_t block_ix = ( (l_ix*q) + (old_slice*(q/4)) ) 
                ; block_ix <= ( (l_ix*q) + ((old_slice+1)*(q/4)) - 1 )
                ; ++block_ix
               )
            {   
                W[W_ix] = block_ix; 
                ++W_ix;
            }     
        }
        if(computed_blocks == 0){
            --W_siz;
        }
    }
    else{
        W_siz = (sl * n) + computed_blocks;
        W = malloc(W_siz * sizeof(size_t));
        
        for(old_slice = 0; old_slice < sl; ++old_slice){
        
            for(  size_t block_ix = ( (l_ix*q) + (old_slice*(q/4)) ) 
                ; block_ix <= ( (l_ix*q) + ((old_slice+1)*(q/4)) - 1 )
                ; ++block_ix
               )
            {
                W[W_ix] = block_ix; 
                ++W_ix;
            }     
        }
        
        /* In this case we take all blocks in the current semgment
         * that have already been transformed, except the block that
         * was transformed in the previous loop cycle. 
         */
        old_slice = sl;
        
        for(size_t block_ix = (  (l_ix*q) + (old_slice*(q/4)) ) 
            ;   block_ix   <= ( ((l_ix*q) + (old_slice*(q/4)) + 
                              (computed_blocks - 1)) )
            ; ++block_ix
           )
        {
            W[W_ix] = block_ix; 
            ++W_ix;
        }  
        
        --W_siz; 
    }
    
    /* Now pick one block index from W[]. This will be z in B[l][z]. */
    
    x  = (J_1 * J_1) / (uint64_t)4294967296;
    y  = (W_siz * x) / (uint64_t)4294967296;
    zz = W_siz - 1 - y;
    z_ix = W[zz]; 
    free(W);
    return z_ix;
}

/*  Each thread processes one segment of the Argon2 memory matrix B[][].
 *  A segment is the intersection of one of the 4 vertical slices, with
 *  a row. Therefore one segment contains many 1024-byte blocks. To be
 *  precise, ( (m' / p) / 4) 1024-byte blocks in a single segment.
 *
 *  The operation of a single thread is the following:
 * 
 *  - Begin the loop that transforms each 1024-byte block in this segment.
 *
 *    Each cycle of that loop does the following:
 *
 *      - Compute J_1 and J_2 in one of 2 ways, using the provided thread input.
 *      - Use J_1 and J_2 to compute indices l and z.
 *      - Call compression function G(), transforming this 1024-byte block.
 *
 *  Input buffer contains: Pointer to start of this thread's segment in B[][] 
 *                         + r, l, sl, m', t, y, p, q as uint64_t's.
 */
void* argon2_transform_segment(void* thread_input){

    /* TESTING ONLY DECLARATIONS BEGIN */
    // clock_t start_1, start_2, start_3, end_1, end_2, end_3;
     
     
     
    
    /* TESTING ONLY DECLARATIONS END  */
    
    /* The first thing in the thread's input buffer
     * is an array of pointers, each pointing to the start of 
     * the respective lane in the working memory matrix B[][].
     *
     * First ever actual necessary use of a triple pointer. Wow.
     */
    block_t **B = *((block_t***)(thread_input))
            ,*G_input_one
            ,*G_input_two
            ,*G_output
            ,*old_block;
             
    
    uint64_t J_1 = 0, J_2 = 0, z_ix, n, j, j_start, j_end
            ,cur_lane = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_l ))
            ,q  = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_q  ))
            ,sl = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_sl ))
            ,r  = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_r  ))
            ,p  = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_p  ))
            ,md = *((uint64_t*)( ((uint8_t*)thread_input) + OFFSET_md ))
            ,computed_blocks = 0;

	uint64_t num_blocks = ceil((double)q / (double)(128 * 4));
	//printf("Computed num_blocks = q/(128*4) which is: %lu\n", num_blocks);
	
	
    block_t* J1J2blockpool = malloc(num_blocks * (1024));


    uint8_t* Z_buf = malloc(6 * sizeof(uint64_t));
    
    memcpy(Z_buf, ((uint8_t*)thread_input) + OFFSET_r, (6 * sizeof(uint64_t)));
    
    old_block = malloc(sizeof(block_t));
    
    /* Determine the start and end control values of this thread's j-loop.    
     * In short, which quarter of this thread's row we're transforming,      
     * in terms of THE INDICES of 1024-byte blocks where the 0th block is
     * the very first block OF THIS LANE, not at the start of B[][]. 
     *         
     * This is in contrast to index z, which is the index of a 1024-byte block
     * relative to the START OF B[][], not to the start of any particular lane.
     */

    /* Let n be the number of 1024-byte blocks in one segment = (m' / p)/4. */
    n = (md / p) / 4;
	//printf("Computed n (blocks in 1 segment) as: n = %lu\n", n);
    /* First block transformed relative to lane start will be (n * (sl + 0))  */
    /* Last  block transformed relative to lane start will be (n * (sl + 1))-1*/  
    j_start = n *  sl;
    j_end   = n * (sl + 1);  
    
    if(r > 0){
        goto label_further_passes;
    }
    
    /* If at first slice (sl=0), we will do 2 fewer cycles of threaded loop, */
    /* as the first 2 loop cycles in pass 0 are hardcoded and different.     */
    if(sl == 0){
        j_start = 2;
        computed_blocks = 2;
    } 
    
    argon2_initJ1J2_blockpool_for2i(Z_buf, J1J2blockpool, num_blocks); 
    
    for(j = j_start; j < j_end; ++j){
    	//start_3 = clock();
    	//printf(
    	//		"Argon2 segment loop: j = %lu to %lu; at slice: %lu\n"
    	//	   , j, j_end, sl
    	//	);
    	
        /* If pass number r=0 and slice number sl=0,1:  */
        /* compute 32-bit values J_1, J_2 for Argon2i.  */
        if( r == 0 && sl < 2 ){
        
        	//start_2 = clock();
 
            
            /* Extract J_1 and J_2. */
			J_1 = *((uint32_t*)(&(J1J2blockpool[0])));
			
			/* Offset is in terms of BYTES now! */
			J_2 = *((uint32_t*)(((uint8_t*)J1J2blockpool) + (num_blocks * 512)));
           // end_2 = clock();
     		//cpu_time_used2 = ((double) (end_2 - start_2)) / CLOCKS_PER_SEC; 
     		
        }   
        /* Otherwise: get J_1, J_2 for Argon2d. */
        else{
            J_1 = *(((uint32_t*)(&(B[cur_lane][j-1]))) + 0);
            J_2 = *(((uint32_t*)(&(B[cur_lane][j-1]))) + 1);
        }
        
        //start_1 = clock();


        z_ix = Argon2_getLZ(r, sl, cur_lane, p, J_1, J_2, n, q,computed_blocks);

       // end_1 = clock();
       // cpu_time_used1 = ((double) (end_1 - start_1)) / CLOCKS_PER_SEC;  
     
     
        /* Now we're ready for this loop cycle's call to G(). */
        
        /* Prepare input arguments of G().
         * These will be pointers directly to the two 1024-byte blocks
         * that will be read by G() as its algorithmic input, and one
         * pointer directly to the start of the 1024-byte block that
         * G() will transform. They are of type block_t*
         */
        
        /* j is the index of the block we're about to transform in this
         * loop cycle RELATIVE TO THE START OF THE CURRENT LANE!!!
         */ 
        G_input_one = (B[0] + (cur_lane*q)) + (j-1);
        G_output    = (B[0] + (cur_lane*q)) + (j);
        
        /* On the other hand, z is the index of the block we feed as second
         * input to G() RELATIVE TO THE START OF B[][] ITSELF!! Not relative
         * to the start of lane l_ix. l_ix was already taken into account
         * when computing index z. It's relative to start of B[][].
         */
     
        
        G_input_two = B[0] + z_ix;
        
        /*
        pthread_mutex_lock(&lock); 
        
        printf("ON PASS: %lu\n\n", r);
		printf("TWO INPUT BLOCKS addr: %p and %p\n", G_input_one, G_input_two);
        printf("WRITING TO BLOCK (slice[%lu]): block addr: %p\n", sl, G_output);
        printf("B[0] has address: %p\n", B[0]);
        
        printf("INPUT BLOCK 1 to G():\n\n");
	   	for(uint32_t i = 0; i < 1024; ++i){
			if(i % 16 == 0 && i > 0){printf("\n");}
			printf("%02x ", ( ((uint8_t*)(G_input_one))[i] )) ;
		}
		printf("\n\n"); 
		
		printf("INPUT BLOCK 2 to G():\n\n");
	   	for(uint32_t i = 0; i < 1024; ++i){
			if(i % 16 == 0 && i > 0){printf("\n");}
			printf("%02x ", ( ((uint8_t*)(G_input_two))[i] )) ;
		}
		printf("\n\n"); 
    	*/
        
        Argon2_G((uint8_t*)G_input_one, (uint8_t*)G_input_two, (uint8_t*)G_output); 
        
		/*
		printf("TRANSFORMED BLOCK BY G():\n\n");
	   	for(uint32_t i = 0; i < 1024; ++i){
			if(i % 16 == 0 && i > 0){printf("\n");}
			printf("%02x ", ( ((uint8_t*)(G_output))[i] )) ;
		}
		printf("\n\n"); 
		
		pthread_mutex_unlock(&lock); 
        */
        
        ++computed_blocks;       
        
       // end_3 = clock();
       // cpu_time_used_total = ((double) (end_3 - start_3)) / CLOCKS_PER_SEC; 
        
        /* What % of total time for 1 loop run took getLZ and getJ1J2_for2i. */
        //printf(
        //		"\n\nget_LZ\t\t percentage of 1 loop cycle: %lf\n"
        //	   , ( (cpu_time_used1*100)/ cpu_time_used_total )
        //	   );
        //	   
        //	   
       // printf(
        //		"get_J1J2_for2i\t percentage of 1 loop cycle: %lf\n"
        //	   , ( (cpu_time_used2*100)/ cpu_time_used_total )
        //	   );
            
    }
    goto label_finish_segment;
    
label_further_passes:   
    /* Always compute them for Argon2d here, as pass number r > 0 always. */
    
    /* STRANGE THING IN RFC EXPLANATION:
     *
     * It asks you to compute J_1 and J_2 for Argon2d for further passes, and
     * this includes the process of computing the 0th block of the lane, but
     * for Argon2d, J_1 and J_2 are the first and next 32 bits of the previous
     * block, but in this case we're already at block index [0], so what did 
     * they mean here as the previous block?? Do we use this block or go back
     * one lane up or what?? 
     *
     * UPDATE: For now I just assume they're basing the block from which we 
     *         take bytes for J1 and J2 on the first argument to G(), not 
     *         the target block. Which would mean for block 0 here we take 
     *         bytes from the LAST block of that lane for J1 and J2.
     */
     if(sl == 0){
        J_1 = (uint64_t)*(((uint32_t*)(&(B[cur_lane][q-1]))) + 0);  
        J_2 = (uint64_t)*(((uint32_t*)(&(B[cur_lane][q-1]))) + 1);
        
        /* We're populating W[] (the set of block indices we pick from when
         * computing indices l and z) in this case from all blocks in this
         * lane. I think? The RFC doesn't say anything specific about this.
         */
        computed_blocks = n;
        sl = 3;
        z_ix = Argon2_getLZ(r, sl, cur_lane, p, J_1, J_2, n, q,computed_blocks);
        
        G_input_one = (B[0] + (cur_lane*q)) + (q-1);
        G_output    = (B[0] + (cur_lane*q));
        G_input_two =  B[0] + z_ix;
        
        /* Before we let G() write to the output block, copy it over and save it
         * here so we can later XOR the result G() wrote there with the old
         * block that was there before G() overwrote it. XORing it with its old
         * contents is the NEW NEW block that will ultimately reside there.
         */
        memcpy(old_block, G_output, sizeof(block_t));
      
        Argon2_G((uint8_t*)G_input_one, (uint8_t*)G_input_two, (uint8_t*)G_output); 
                
        /* XOR the result of G() with the old block. This is now the new block*/
        for(size_t xr = 0; xr < 128; ++xr){
            ((uint64_t*)G_output)[xr] ^= ((uint64_t*)old_block)[xr];
        }  
        /* If at first slice (sl=0), we will do 1 cycle less of threaded loop */
        /* as the first 1024-byte block in passes 1+ is hardcoded.            */
        j_start = 1;
        computed_blocks = 1;
        sl = 0;
    } 
    for(j = j_start; j < j_end; ++j){

        J_1 = (uint64_t)*(((uint32_t*)(&(B[cur_lane][j-1]))) + 0);  
        J_2 = (uint64_t)*(((uint32_t*)(&(B[cur_lane][j-1]))) + 1);

        z_ix = Argon2_getLZ(r, sl, cur_lane, p, J_1, J_2, n, q,computed_blocks);

        G_input_one = (B[0] + (cur_lane*q)) + (j-1);
        G_output    = (B[0] + (cur_lane*q)) + (j);       
        G_input_two =  B[0] + z_ix;
                
        /* Before we let G() write to the output block, copy it over and save it
         * here so we can later XOR the result G() wrote there with the old
         * block that was there before G() overwrote it. XORing it with its old
         * contents is the NEW NEW block that will ultimately reside there.
         */
        memcpy(old_block, G_output, sizeof(block_t));
        
        
        /*
        pthread_mutex_lock(&lock); 
        
        printf("ON PASS: %lu\n\n", r);
		printf("TWO INPUT BLOCKS addr: %p and %p\n", G_input_one, G_input_two);
        printf("WRITING TO BLOCK (slice[%lu]): block addr: %p\n", sl, G_output);
        printf("B[0] has address: %p\n", B[0]);
        
        pthread_mutex_unlock(&lock); 
        */
        
        
        Argon2_G((uint8_t*)G_input_one, (uint8_t*)G_input_two, (uint8_t*)G_output); 
        
        /* XOR the result of G() with the old block. This is now the new block*/
        for(size_t xr = 0; xr < 128; ++xr){
            ((uint64_t*)G_output)[xr] ^= ((uint64_t*)old_block)[xr];
        }  
        
        ++computed_blocks;           
    }    
   
label_finish_segment:

    free(Z_buf);
    free(old_block);
    free(J1J2blockpool); 

    return NULL;
}
   
    
void Argon2_MAIN(struct Argon2_parms* parms, uint8_t* output_tag){
	
	/* MUTEX FOR TESTING ONLY SO WE CAN SEE PRINTS IN G() properly. */
    pthread_mutex_init(&lock, NULL);
    
    /* Length of input to the generator of 64-byte H0, BLAKE2B() in this case.*/
    uint64_t H0_input_len =   10 * sizeof(uint32_t)
                            + parms->len_P + parms->len_S
                            + parms->len_K + parms->len_X
                           ;
                           
    /* Input to the generator of H0. */
    uint8_t *H0_input      = malloc(H0_input_len),
            *final_block_C = malloc(sizeof(block_t));
         
     
    /* Construct the input buffer to H{64}() that generates 64-byte H0. */
    /* The order has to be exactly as specified in the RFC.             */
    *((uint32_t*)(H0_input + 0 )) = *( (uint32_t*)(&(parms->p)) );
    *((uint32_t*)(H0_input + 4 )) = *( (uint32_t*)(&(parms->T)) );
    *((uint32_t*)(H0_input + 8 )) = *( (uint32_t*)(&(parms->m)) );
    *((uint32_t*)(H0_input + 12)) = *( (uint32_t*)(&(parms->t)) );
    *((uint32_t*)(H0_input + 16)) = *( (uint32_t*)(&(parms->v)) );
    *((uint32_t*)(H0_input + 20)) = *( (uint32_t*)(&(parms->y)) );
    
    *((uint32_t*)(H0_input + 24)) = *( (uint32_t*)(&(parms->len_P)) );
    
    size_t H0_in_offset = 28;
      
    memcpy((H0_input + H0_in_offset), parms->P, parms->len_P);
    
    H0_in_offset += parms->len_P;
    
    *((uint32_t*)(H0_input + H0_in_offset)) = *( (uint32_t*)(&(parms->len_S)) );
    
    H0_in_offset += 4;
    
    memcpy((H0_input + H0_in_offset), parms->S, parms->len_S);
    
    H0_in_offset += parms->len_S;
    
    *((uint32_t*)(H0_input + H0_in_offset)) = *( (uint32_t*)(&(parms->len_K)) );
    
    H0_in_offset += 4;
    
    if(parms->len_K){
        memcpy((H0_input + H0_in_offset), parms->K, parms->len_K);
        H0_in_offset += parms->len_K; 
    }
    
    *((uint32_t*)(H0_input + H0_in_offset)) = *( (uint32_t*)(&(parms->len_X)) );
    H0_in_offset += 4;
    
    if(parms->len_X){
        memcpy((H0_input + H0_in_offset), parms->X, parms->len_X);
        H0_in_offset += parms->len_X;  
    }
    
    /* The offset also tells us the total length of the input to H{64}() now.*/
    
    /* Generate H_0 now. */
    uint8_t* H0 = malloc(64);
    
    BLAKE2B_INIT(H0_input, H0_in_offset, 0, 64, H0);

    /* Construct the working memory of Argon2 now. */
    
    /* How many 1024-byte blocks in B. */
    uint64_t m_dash = 4 * parms->p * floor(parms->m / (4 * parms->p));
    
    /* How many columns in B. Also size of one row in 1024-byte blocks. */
    /* Each column intersecting a row is one 1024-byte block.           */
    uint64_t q = m_dash / parms->p;
                      
    /* The best we can do to help simplify the pointer arithmetic here is to 
     * set a pointer to each row of the B[][] memory matrix. Each row consists
     * of many 1024-byte blocks, but at least we will be able to directly use
     * the [index] notation when accessing B[][] for the "get to row X" part
     * as described in the Argon2 RFC specification, ie the first bracket.
     *
     * For the second bracket where B[][] is used in the specification, we will
     * use a specially defined struct that only has a 1024-byte array in it
     * and typedef'd as block_t. This changes the behind-the-scenes multiplier
     * of the C compiler's pointer arithmetic to (* 1024), just like it would
     * do (* 4) behind the scenes for a pointer to uint32_t.
     *
     * To work inside a particular 1024-byte block, we will likely need actual
     * carefully written pointer arithmetic.
     */
    
    /* Allocate the working memory matrix of Argon2. */
    uint8_t* working_memory = malloc(m_dash * sizeof(block_t));
    
    /* Split the memory matrix into p rows by setting pointers to the 
     * start of each row. Each row has many 1024-byte blocks. 
     */
    block_t** B = malloc(parms->p * sizeof(block_t*));
    
    /* Set a pointer to the start of each row in the memory matrix. */
    for(uint64_t i = 0; i < parms->p; ++i){
        B[i] = (block_t*)(working_memory + (i * (q * sizeof(block_t))));
    }
    
    /* Now where B[x][y] is used in the RFC specification, here in this
     * implementation it too can be written as B[x][y], which would mean
     * to the compiler "start from contents of memory address B, wherein is a
     * pointer to a 1024-byte block. Go +x such pointers into B, to get to the
     * actual row x in Argon2's working memory matrix B[][]. Then from
     * this pointer to a 1024-byte block, go +y such blocks, to the 
     * exact 1024-byte block you need and dereference the pointer to it." 
     *
     * All while keeping the entire memory (all p rows of 1024-byte blocks)
     * contiguous in the process memory as required in the RFC specification
     * in order for the security of the hashing algorithm to work.
     */
    
    uint8_t* B_init_buf = malloc(64 + 4 + 4);
    uint32_t zero = 0, one = 1;
    
    memcpy(B_init_buf + 0 , H0, 64); 
    memcpy(B_init_buf + 64, &zero, 4);
    
    printf("\n\n======== NOW INITIALIZING B[all][0] and B[all][1] =======\n\n");
    
    for(uint32_t i = 0; i < parms->p; ++i){
        memcpy(B_init_buf + 64 + 4, &i, 4);   
        Argon2_H_dash(B_init_buf, (uint8_t*)&(B[i][0]), 1024, (64+4+4));
    }
    
    memcpy(B_init_buf + 64, &one, 4);
    
    for(uint32_t i = 0; i < parms->p; ++i){
        memcpy(B_init_buf + 64 + 4, &i, 4); 
        Argon2_H_dash(B_init_buf, (uint8_t*)&(B[i][1]), 1024, (64+4+4));
    }
    
    printf("\n\n======= DONE INITIALIZING B[all][0] and B[all][1] =======\n\n");
    
    /* Counter that keeps track of which Argon2 pass we are currently on. */
    uint64_t r = 0;
    
    /* Each of the 4 vertical slices is computed and finished before the next
     * slice's threads can begin. All threads process their 1/4 rows in that
     * slice in parallel.
     */
    
    /* Create p thread_id's - one for each thread we will run. */
    pthread_t argon2_thread_ids[parms->p];
    
    /* Offset into the input buffer of Argon2 threads. */
    size_t thread_in_offset = 0;
    
    /* Allocate input buffers for each thread.                    */
    /* Each input buffer will contain a pointer and 8 uint64_t's. */
    void** thread_inputs = malloc(parms->p * sizeof(void*));
    
    for(uint32_t i = 0; i < parms->p; ++i){
        thread_inputs[i] = malloc(sizeof(block_t*) + (8 * sizeof(uint64_t)));
    }
    
label_start_pass:

    // printf("ARGON2id at CURRENT PASS r = %lu\n", r);
     
    for (uint64_t sl = 0; sl < 4; ++sl){ /* slice number. */
        //printf("\tARGON2id at CURRENT SLICE sl = %lu\n", sl);
        for(uint64_t i = 0; i < parms->p; ++i){ /* lane/thread number. */
           // printf("\t\tARGON2id now starting LANE = %lu\n", i);        
            /*  Third for-loop 3.1 that will:                            
             *  Set loose a thread for each row of blocks in the matrix.    
             *  21845 1024-byte blocks will be processed by each thread. 
             *  provided 2 gigibytes of memory usage and 24 threads.     
             *
             *  Each thread will call G() in a for-loop going over each
             *  1024-block in that segment of the working memory matrix.
             * 
             *  For that reason, each thread will need INPUT:
             * 
             *  - Pointer to start of segment to be transformed by that thread,
             *    based on which we will take G()'s i/o 1024-byte blocks.
             *  - Parameters that are constant during a thread's operatrion for
             *    computing J_1 and J_2 for Argon2i: r, l, sl, m', t, y, p, q
             *       
             *  Third for-loop 3.2 that will join all threads before the  
             *  the next set of threads can be set loose on next vertical 
             *  slice (set of segments, each of which is a set of 1024-byte 
             *  blocks) of the working memory matrix B[][].
             */
             
             
            /* Populate this thread's input buffer before starting it. */
            
            /* First is a pointer to the start of the memory matrix B[][]. */
            *((block_t***)(((uint8_t*)(thread_inputs[i])) + 0)) = B;
            
            /* Offset in bytes into the thread's input buffer. */
            thread_in_offset = sizeof(block_t*);
           
            
            /* Second is r, the current pass number. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) = r;   
            thread_in_offset += sizeof(uint64_t);
            
            /* Third is l, the current lane number. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) = i;
            thread_in_offset += sizeof(uint64_t);
            
            /* Fourth is sl, the current slice number. */ 
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) = sl;
            thread_in_offset += sizeof(uint64_t);
            
            /* Now m', the total number of 1024-byte blocks in the matrix. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) 
            = m_dash;   
            thread_in_offset += sizeof(uint64_t);
            
            /* Sixth is t, the total number of passes. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) 
            = parms->t;
            thread_in_offset += sizeof(uint64_t);
            
            /* Seventh is y, the Argon2 type. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) 
            = parms->y;
            thread_in_offset += sizeof(uint64_t);
            
            /* Eighth is p, the total number of threads Argon2 should use. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) 
            = parms->p;
            thread_in_offset += sizeof(uint64_t);
            
            /* Ninth is q, the total number of 1024-byte blocks in 1 row. */
            *((uint64_t*)(((uint8_t*)(thread_inputs[i])) + thread_in_offset)) = q;
            thread_in_offset += sizeof(uint64_t);
            
            /* Now that the input buffer for this thread is ready, start it. */
            pthread_create(
                 &(argon2_thread_ids[i])
                ,NULL
                ,argon2_transform_segment
                ,thread_inputs[i]
            );
             
        }
        
        /* After the previous loop starts all threads, this loop joins them. 
         * All segments of this slice of the memory matrix must be finished 
         * before any thread can start processing its segment of next slice.
         */
        for(uint64_t i = 0; i < parms->p; ++i){
            pthread_join(argon2_thread_ids[i], NULL);    
        } 

    } /* End of one slice. */


	printf("END OF PASS [%lu] BLOCK 0:\n\n", r);
   	for(uint32_t i = 0; i < 1024; ++i){
		if(i % 16 == 0 && i > 0){printf("\n");}
		printf("%02x ", ( ((uint8_t*)(&(B[0][0])))[i] )) ;
	}
	printf("\n\n"); 
	printf("END OF PASS [%lu] BLOCK 31:\n\n", r);
   	for(uint32_t i = 0; i < 1024; ++i){
		if(i % 16 == 0 && i > 0){printf("\n");}
		printf("%02x ", ( ((uint8_t*)(&(B[3][7])))[i] )) ;
	}
	printf("\n\n"); 

    /* Finished all 4 slices of a pass. Increment pass number.*/
    ++r;
    
    /* If Argon2 is to perform more than the zeroth pass, do them. */
    if (r < parms->t){
        goto label_start_pass;    
    }
    
    
      
    /* Done with all required passes. */
    /* Compute final 1024-byte block C by XORing the last block of every lane.*/ 
 
    memcpy(final_block_C, &(B[0][q-1]), 1024);
    
    /*
    printf("last column blocks of B[][] at end of 1st pass:\n");
	for(size_t ln = 0; ln < parms->p; ++ln){
			printf("LAST 1024-byte BLOCK IN LANE %lu:\n", ln);
           	for(uint32_t i = 0; i < 1024; ++i){
				if(i % 16 == 0 && i > 0){printf("\n");}
				printf("%02x ", ( ((uint8_t*)(&(B[ln][q-1])))[i] )) ;
			}
    		printf("\n\n");  
     
    }
	*/    
    	
    for(size_t ln = 1; ln < parms->p; ++ln){
    
    /*
		printf("\n\n***** final block before XORing with last block of ln"
			   " = %lu *****\n\n"
			  ,ln);
		
		for(uint32_t i = 0; i < 1024; ++i){
		    if(i % 16 == 0 && i > 0){printf("\n");}
		    printf("%02x ", (uint8_t)final_block_C[i]);
		}
    	printf("\n\n");  
    	*/
    	   
        for(size_t xr = 0; xr < 128; ++xr){
           ((uint64_t*)(final_block_C))[xr] ^= ((uint64_t*)(&(B[ln][q-1])))[xr];  
        }        
    }
       
    /* Finally, feed final block C to H' producing Tag-length bytes of output:
     * Result = H'{T}(C)
     */
    printf("\n\n***** input 1024-byte block to H_dash calling B2B: *****\n\n");
    
    for(uint32_t i = 0; i < 1024; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)final_block_C[i]);
    }
    printf("\n\n");     
    
    Argon2_H_dash(final_block_C, output_tag, parms->T, 1024);
 
    /* Cleanup. */    
    for(uint32_t i = 0; i < parms->p; ++i){
        free(thread_inputs[i]); 
    }    
    free(thread_inputs);
    free(B_init_buf);
    free(B);
    free(working_memory);
    free(H0);
    free(H0_input);
    free(final_block_C);
}


/* The caller must have made sure in advance that X and Y are each L-limb, 
 * L being the number of (non-zero-padded) limbs in the Montgomery modulus N.
 *
 * If X and Y are Montgomery representatives of A and B, then this algorithm
 * computes R, the Montgomery representative of (A*B).
 *
 * This algorithm can also be used to convert from base-2 of a number to the
 * base-beta Montgomery representative of the same number, and also to go
 * back from Montgomery representative to base-2.
 *
 * I use base-2^64 Montgomery representatives, which means beta=2^64. This leads
 * to having 64-bit limbs in the Montgomery representatives of numbers. It also
 * leads to having 64-bit MUL and ADD operations, which are not directly 
 * supported in C, instead most C compilers provide intrinsics for it, which we
 * make use of here to boost performance. Here, L = ceil(N_used_bits / 64).
 *
 * Note: beta is ignored everywhere where we'd multiply by it, so don't even
 *       pass it here.
 */
void Montgomery_MUL(struct bigint* X, struct bigint* Y, 
					struct bigint* N, struct bigint* R
				   )
{
	
	uint8_t C, D;
	unsigned long long Ul, Uh, Vl, Vh, W, *T, q;
	struct bigint R_aux;
	bigint_create(&R_aux, R->size_bits, 0);
	
	/* Set R = 0, all of its (L+1) limbs. */
	bigint_nullify(R);
	
	/* T - 3-limb variable, q - 1-limb variable. */
	/* Keep T temporarily as part of R->bits in limbs [l+1] to [l+3]. */
    T = (unsigned long long*)(R->bits + ((MONT_L + 1) * MONT_LIMB_SIZ)); 
	memset(T, 0x00, (3 * MONT_LIMB_SIZ));
	
	for(uint64_t i = 0; i < MONT_L; ++i){
		/* 2. */
		Ul = _mulx_u64(  *((uint64_t*)(Y->bits + (i * MONT_LIMB_SIZ)))
						,*((uint64_t*)(X->bits))
						,&Uh
					  );
					  
	    C = _addcarryx_u64((uint8_t)0, Ul, *((uint64_t*)R->bits), &Ul);
	    
	    Uh += (uint64_t)C;

	    *(T + 0) = Ul;
	    *(T + 1) = Uh;
	    *(T + 2) = 0;	
	    
		/* 3. */
		q = _mulx_u64((uint64_t)MONT_MU, *(T + 0), &Uh);
		
		/* 3.5:  T += q*n0. */
		Vl = _mulx_u64(q, *((uint64_t*)(N->bits + (0*MONT_LIMB_SIZ))), &Vh);
		
		C = _addcarryx_u64( (uint8_t)0, *(T + 0), Vl, (T + 0) );
		
		D = _addcarryx_u64( C, *(T + 1), Vh, (T + 1) );
	
		*(T + 2) += (uint64_t)D;
		
		/**(T + 2) = 0;*/
		
		
		/* 4. */
		for(uint64_t j = 1; j < MONT_L; ++j){
			/* Compute T. */
			Ul = _mulx_u64(q, *((uint64_t*)(N->bits + (j*MONT_LIMB_SIZ))), &Uh);
			
			
			Vl = _mulx_u64( *((uint64_t*)(Y->bits + (i * MONT_LIMB_SIZ)))
						   ,*((uint64_t*)(X->bits + (j * MONT_LIMB_SIZ)))
						   ,&Vh
						  );
						  
			C = _addcarryx_u64((uint8_t)0
							  ,Ul
							  ,*((uint64_t*)(R->bits+(j * MONT_LIMB_SIZ)))
							  ,&Ul
							  );			  
						  
			Uh += (uint64_t)C;			  
						  
			D = _addcarryx_u64((uint8_t)0, Vl, *(T + 1), &Vl);
			
			C = _addcarryx_u64((uint8_t)0, Ul, Vl, (T + 0));
			
			D = _addcarryx_u64(D, Uh, Vh, &W);
			
			C = _addcarryx_u64(C, W, *(T + 2), (T + 1));
			
			*(T + 2) = (uint64_t)C + (uint64_t)D;
					  
			/* Set r_(j-1) = t_0  */
			*((uint64_t*)(R->bits + ((j-1) * MONT_LIMB_SIZ))) = *(T + 0);
		}

		/* 5. */	
		
		C = _addcarryx_u64( (uint8_t)0
				   ,*(T + 1)
				   ,*((uint64_t*)(R->bits+(MONT_L * MONT_LIMB_SIZ)))
				   , (T + 0)
				  );
		
		
		/*D = _addcarryx_u64(C, *(T+1), 0, (T+1));*/
		
		*(T + 1) = (uint64_t)C + *(T + 2); 
		*(T + 2) = 0;
		/* 6. */ 
		*((uint64_t*)(R->bits+((MONT_L - 1) * MONT_LIMB_SIZ))) = *(T + 0);
		*((uint64_t*)(R->bits+( MONT_L      * MONT_LIMB_SIZ))) = *(T + 1);	
	}

	memset((uint8_t*)T, 0x00, 3 * MONT_LIMB_SIZ);

	/* 7. */
	R->used_bits = get_used_bits(R->bits, (uint32_t)(R->size_bits / 8));
	R->free_bits = R->size_bits - R->used_bits;
	
	 if ( *((uint64_t*)(R->bits + (MONT_L * MONT_LIMB_SIZ))) != 0){ 
	/*if ( (bigint_compare2(R, N)) != 3 ){*/
		printf("---->> We hit the R_L != 0 case at end of Mont_MUL!\n");
		/* Standard BigInt subtraction.  */
		bigint_equate2(&R_aux, R);		
		bigint_sub2(&R_aux, N, R);
	}
	
	free(R_aux.bits);
	return;
	
}

/*  PRACTICAL METHOD TO OBTAIN A MONTGOMERY REPRESENTATIVE
 *  
 *	To find the Montgomery representative (mod M) of A, do the following:
 *
 *  Call Montgomery MUL mod M with input one set to (beta^(2*L) mod M), the 
 *	other input set to A itself (in normal PSN notation). The output of this
 *  will in fact be a valid Montgomery representative of A.
 */
void Get_Mont_Form(struct bigint *src, struct bigint *target, struct bigint* M){

	struct bigint two, sixtyfour, beta, two_L, aux;
	
	bigint_create(&two, 	  M->size_bits, 2 );					
	bigint_create(&sixtyfour, M->size_bits, 64);
	bigint_create(&beta,	  M->size_bits, 0 );
	bigint_create(&aux,       M->size_bits, 0 );
	bigint_create(&two_L,	  M->size_bits, 2 * MONT_L );
  	
  	bigint_nullify(target);
  	
    /* beta = 2^64 for 64-bit Montgomery limbs. */
    bigint_pow(&two, &sixtyfour, &beta);
    
    /* aux = beta^(2*L) mod M */
    bigint_mod_pow(&beta, &two_L, M, &aux);

    /* Now generate the source's Montgomery form. */
    Montgomery_MUL(&aux, src, M, target);
    
    target->used_bits = get_used_bits(target->bits, (uint32_t)(M->size_bits/8));
    target->free_bits = target->size_bits - target->used_bits;
 					 
    printf("[OK] Cryptolib: Montgomery Form computed successfully.\n");
    return;
}

/* Computes B^P mod M using Montgomery Modular Multiplication. Result goes in R.
 * The base B must be in Montgomery Form. 
 * The result R is NOT the Montgomery Form of the result of powering, it
 * is the actual result in regular positional notation.
 *
 * Note: This function is somewhat general, but not fully general - it computes
 *	 	 any modular powering mod M using Montgomery Multiplication, and the
 *       parameters that depend on the modulus M (MU and L) are defined at
 *		 the top of this file. However, it won't work for modular powering mod
 *       some other number, other than M, which for the purposes of the secure
 *       chat system this library was originally written for is global static.
 *		 If a function for modular POW mod M using Montgomery Multiplication
 *		 for a different modulus is needed, you have to change the Montgomery
 *       parameters MU and L - they are different for each Montgomery modulus.
 */
void MONT_POW_modM(struct bigint* B, struct bigint* P,
				   struct bigint* M, struct bigint* R)
{
	uint32_t bit = 0;
	struct bigint X, Y, R_1, one, div_res;
    bigint_create(&X,  		M->size_bits, 0);
    bigint_create(&Y,  		M->size_bits, 0);
    bigint_create(&R_1, 	M->size_bits, 0);
    bigint_create(&one, 	M->size_bits, 1);
    bigint_create(&div_res, M->size_bits, 0);
  
    /* X and Y both become equal to the passed base B */
    bigint_equate2(&X, B);
    bigint_equate2(&Y, B);

    for(uint32_t i = P->used_bits - 2; i >= 0; --i){ 	

   		
    	Montgomery_MUL(&Y, &Y, M, R);   	
	    bigint_equate2(&Y, R);
		

		
    	if( (BIGINT_GET_BIT(*P, i, bit)) == 1 ){
			Montgomery_MUL(&Y, &X, M, R);		
			bigint_equate2(&Y, R);		
    	}

    	if(i==0){break;}
    }
	
	Montgomery_MUL(&one, R, M, &R_1);
	bigint_div2(&R_1, M, &div_res, R);	
	
	free(X.bits); free(Y.bits); free(R_1.bits);
	free(one.bits); free(div_res.bits);
	return;
}

/* Generate a cryptographic signature of a sender's message
 * according to the method pioneered by Claus-Peter Schnorr.
 *
 * PH = BLAKE2B{64}(data);
 *  k = (BLAKE2B{64}(a || PH) mod (Q-1)) + 1;
 *  R = G^k mod M;
 *  e = trunc{bitwidth(Q)}(BLAKE2B{64}(R || PH));
 *  s = ((k - (a * e)) mod Q;
 *
 * where M is a 3071-bit prime number, Q is a 320-bit prime
 * number which exactly dibides (M-1), G = 2^((M-1)/Q) mod M,
 * and a is the private key of the message sender. 
 *
 * The signature itself is (s,e).
 */ 
void Signature_GENERATE(struct bigint* M, struct bigint* Q, struct bigint* Gmont 
                       ,uint8_t* data, uint64_t data_len, uint8_t* signature
                       ,struct bigint* private_key, uint64_t key_len_bytes
                       )
{

    struct bigint second_btb_outnum, one, Q_minus_one, reduced_btb_res,
                  k, R, e, s, div_res, aux1, aux2, aux3;
        
    bigint_create(&second_btb_outnum,  M->size_bits, 0);
    bigint_create(&Q_minus_one,     M->size_bits, 0);
    bigint_create(&reduced_btb_res, M->size_bits, 0);
    bigint_create(&div_res,         M->size_bits, 0);
    
    bigint_create(&one,  M->size_bits, 1);
    bigint_create(&k,    M->size_bits, 0);
    bigint_create(&R,    M->size_bits, 0);
    bigint_create(&e,    M->size_bits, 0);
    bigint_create(&s,    M->size_bits, 0);
    bigint_create(&aux1, M->size_bits, 0);
    bigint_create(&aux2, M->size_bits, 0);
    bigint_create(&aux3, M->size_bits, 0);
    
    /* Compute the signature generation prehash. */
    uint64_t prehash_len = 64
    		,len_key_PH = prehash_len + key_len_bytes
    		,R_used_bytes = R.used_bits
            ,len_Rused_PH
            ;
            
    uint8_t* prehash = malloc(prehash_len);   
    memset(prehash, 0x00, prehash_len);
         
    BLAKE2B_INIT(data, data_len, 0, prehash_len, prehash);
    
    printf("\n\n[SIG_GEN] BLAKE2b produced 64-byte PREHASH:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)prehash[i]);
    }
    printf("\n\n");
    
    uint8_t *second_btb_outbuf = malloc(64)
        ,*second_btb_inbuf  = malloc(key_len_bytes + prehash_len);
        
    memcpy(second_btb_inbuf, private_key->bits, key_len_bytes);
    memcpy(second_btb_inbuf + key_len_bytes, prehash, prehash_len);
    
    BLAKE2B_INIT(second_btb_inbuf, len_key_PH, 0, 64, second_btb_outbuf);
    
	
    
    /* Now compute k. */  
    memcpy(second_btb_outnum.bits, second_btb_outbuf, 64);
    
    second_btb_outnum.used_bits = get_used_bits(second_btb_outnum.bits, 64);
    
    second_btb_outnum.free_bits = second_btb_outnum.size_bits 
    							  - 
    							  second_btb_outnum.used_bits;
    
    bigint_sub2(Q, &one, &Q_minus_one);    
    bigint_div2(&second_btb_outnum, &Q_minus_one, &div_res, &reduced_btb_res);  
    bigint_add_fast(&reduced_btb_res, &one, &k);  /* <----- k */ 
    
    printf("Signature generator computed k:\n");
    bigint_print_info(&k);
    bigint_print_bits(&k);
    
    printf("k in big-endian:\n");
    bigint_print_bits_bigend(&k);
    /* Now compute R. */

	MONT_POW_modM(Gmont, &k, M, &R); 
 
	printf("Montgomery R = G^k mod M FINISHED!!!  R:\n\n");
	bigint_print_info(&R);
	bigint_print_bits(&R);
	
	printf("R in big-endian:\n");
	bigint_print_bits_bigend(&R);
	
	R_used_bytes = R.used_bits;
	
    while(R_used_bytes % 8 != 0){
        ++R_used_bytes;
    }
    
    R_used_bytes /= 8;
    
    /* Now compute e. */
    uint8_t *R_with_prehash = malloc(R_used_bytes + prehash_len),
         *e_buf = malloc(40), /* e has bitwidth of Q. */
         *third_btb_outbuf = malloc(64);
         
    memcpy(R_with_prehash, R.bits, R_used_bytes);
    memcpy(R_with_prehash + R_used_bytes, prehash, prehash_len);
    
    len_Rused_PH = R_used_bytes + prehash_len;
    
    printf("[SIG_GEN] Parameters to B2B producing 64-byte e:\n");
    printf("parm 1 - R_with_prehash:\n\n");
    
    for(uint32_t i = 0; i < len_Rused_PH; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)R_with_prehash[i]);
    }
    printf("\n\n");
    
    printf("parm 2 - len_Rused_PH: %lu\n\n", len_Rused_PH);
    printf("parm 3 - 0\n\n");
    printf("parm 4 - 64\n\n");
    printf("parm 5 - out_buf\n\n");
    
    BLAKE2B_INIT(R_with_prehash, len_Rused_PH, 0, 64, third_btb_outbuf);
    
    printf("\n\n[SIG_GEN] BLAKE2b(R||PH) produced 64-byte e:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)third_btb_outbuf[i]);
    }
    printf("\n\n");
    
    memcpy(e.bits, third_btb_outbuf, 40);

    e.used_bits = get_used_bits(e.bits, 40);
    e.free_bits = e.size_bits - e.used_bits;
        
    /* Lastly, compute s = ( k + ((Q-a)×e) ) mod Q */
    bigint_sub2(Q, private_key, &aux1);

    bigint_mul_fast(&aux1, &e, &aux2);
   
    bigint_add_fast(&aux2, &k, &aux3);
    
    bigint_div2(&aux3, Q, &div_res, &s);
    
    printf("Signature generator computed e and s!!\ne:\n");
    bigint_print_info(&e);
    bigint_print_bits(&e);
    printf("s:\n");
    bigint_print_info(&s);
    bigint_print_bits(&s);    
    
    /* signature buffer must have been allocated with exactly 
     * ( (2 * sizeof(struct bigint)) + (2 * bytewidth(Q)) )
     * bytes of memory. No checks performed for performance.
     */
    uint32_t offset = 0;
    memcpy(signature + offset, &s, sizeof(struct bigint));
    offset += sizeof(struct bigint);
    memcpy(signature + offset, s.bits, 40);
    offset += 40;
    memcpy(signature + offset, &e, sizeof(struct bigint));
    offset += sizeof(struct bigint);
    memcpy(signature + offset, e.bits, 40);
    
    /* Cleanup. */
    free(second_btb_outnum.bits);
    free(one.bits); 
    free(Q_minus_one.bits); 
    free(reduced_btb_res.bits); 
    free(k.bits); 
    free(R.bits); 
    free(s.bits);    
    free(div_res.bits); 
    free(aux1.bits); 
    free(aux2.bits); 
    free(aux3.bits);
    free(prehash);
    free(second_btb_outbuf); 
    free(second_btb_inbuf); 
    free(e_buf);    
    free(R_with_prehash); 
    free(third_btb_outbuf); 
    free(e.bits);  
     
    return;
}


/*
 *  To verify against public key A and whatever was signed, the receiver:
 *
 *	0. checks that 0 <= s < Q, and that e has the expected bitwidth (that of Q).
 *
 *	1. Computes the prehash PH as in step 0. above.
 *
 *	2. Computes R = (G^s * A^e) mod M.
 *
 *	3. Computes BLAKE2B{64}(R||PH), truncated to bitwidth of Q. 
 *	   Check that this is equal to e. If it is, validation passed. 
 * 	   In any other circumstance, the validation fails.
 *
 *	RETURNS: 1 if signature is valid for this message, 0 for invalid signature.
 *
 */
uint8_t Signature_VALIDATE(struct bigint* Gmont, struct bigint* Amont,
						   struct bigint* M,     struct bigint* Q, 
						   struct bigint* s, 	 struct bigint* e,
						   uint8_t* data, uint32_t data_len)
{
	if(bigint_compare2(s, Q) != 3){
		printf("[INFO] Cryptolib: sig_validate: passed s =/= passed Q.\n");
		return 0;		
	}

    uint64_t prehash_len = 64
    		,R_used_bytes
            ,len_Rused_PH
            ;
            
    uint8_t* prehash = malloc(prehash_len);   
    memset(prehash, 0x00, prehash_len);
    
    
    struct bigint R, R_aux1, R_aux2, R_aux3, div_res, val_e;
    
    bigint_create(&R, 	   	M->size_bits, 0);
    bigint_create(&R_aux1, 	M->size_bits, 0);
    bigint_create(&R_aux2,	M->size_bits, 0);
    bigint_create(&R_aux3, 	M->size_bits, 0);
    bigint_create(&div_res, M->size_bits, 0); 
    bigint_create(&val_e,	M->size_bits, 0);
    
    /* Compute the signature validation prehash. Same as during generation. */ 
      
    BLAKE2B_INIT(data, data_len, 0, prehash_len, prehash);

	printf("\n\n[SIG_VAL] BLAKE2b produced 64-byte PREHASH:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)prehash[i]);
    }
    printf("\n\n");


    /* Compute  R =  (G^s * A^e) mod M. 			  */
    /* This is: R = ((G^s mod M) * (A^e mod M)) mod M */

	printf("[SIG_VAL] s in big-endian:\n");
	bigint_print_bits_bigend(s);
	
	printf("[SIG_VAL] e in big-endian:\n");
	bigint_print_bits_bigend(e);

	MONT_POW_modM(Gmont, s, M, &R_aux1); 
	MONT_POW_modM(Amont, e, M, &R_aux2);
	
	bigint_mul_fast(&R_aux1, &R_aux2, &R_aux3);
	
	bigint_div2(&R_aux3, M, &div_res, &R);
	
	printf("[SIG_VAL] R_val = (G^s * A^e) mod M   FINISHED!!!  R_val:\n\n");
	bigint_print_info(&R);
	bigint_print_bits(&R);
	
	printf("[SIG_VAL] R_val in big-endian:\n");
	bigint_print_bits_bigend(&R);
	
	
	R_used_bytes = R.used_bits;
	  
    while(R_used_bytes % 8 != 0){
        ++R_used_bytes;
    }
    
    R_used_bytes /= 8;
    
    /* Last step: 															*/
    /* Computes val_e = BLAKE2B{64}(R||PH), truncated to bitwidth of Q. 	*/
 	/* Check that this is equal to e. If it is, validation passed. 			*/
 	
 	/* Now compute val_e. */
    uint8_t *R_with_prehash = malloc(R_used_bytes + prehash_len),
         /* *e_buf = malloc(40), */ /* e has bitwidth of Q. */
         *third_btb_outbuf = malloc(64); /* Not rlly 3rd here. Change it. */
         
    memcpy(R_with_prehash, R.bits, R_used_bytes);
    memcpy(R_with_prehash + R_used_bytes, prehash, prehash_len);
    
    len_Rused_PH = R_used_bytes + prehash_len;
    
    
    
    printf("[SIG_VAL] Parameters to B2B producing 64-byte e:\n");
    printf("parm 1 - R_with_prehash:\n\n");
    
    for(uint32_t i = 0; i < len_Rused_PH; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)R_with_prehash[i]);
    }
    printf("\n\n");
    
    printf("parm 2 - len_Rused_PH: %lu\n\n", len_Rused_PH);
    printf("parm 3 - 0\n\n");
    printf("parm 4 - 64\n\n");
    printf("parm 5 - out_buf\n\n");
    
    
    
    BLAKE2B_INIT(R_with_prehash, len_Rused_PH, 0, 64, third_btb_outbuf);
    
    
    printf("\n\n[SIG_VAL] BLAKE2b produced 64-byte e_val:\n\n");
    
    for(uint32_t i = 0; i < 64; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)third_btb_outbuf[i]);
    }
    printf("\n\n");
    
    memcpy(val_e.bits, third_btb_outbuf, 40);

    val_e.used_bits = get_used_bits(val_e.bits, 40);
    val_e.free_bits = val_e.size_bits - val_e.used_bits;
    
    
    if( bigint_compare2(e, &val_e) != 2 ){
    	printf("[INFO] Cryptolib: SIG_VAL: val_e =/= passed e. Ret 0.\n");
    	
    	printf("Passed e:\n");
    	bigint_print_info(e);
    	bigint_print_bits(e);
    	
    	printf("Computed val_e:\n");
    	bigint_print_info(&val_e);
    	bigint_print_bits(&val_e);
    	
    	return 0;
    }

    free(prehash);   
    free(R.bits);
    free(R_aux1.bits);
    free(R_aux2.bits);
    free(R_aux3.bits);
    free(div_res.bits); 
    free(val_e.bits);
    free(R_with_prehash);
    /*free(e_buf);*/
    free(third_btb_outbuf); /* Not rlly 3rd here. Change it. */
    
    return 1;
	
}
    

            

