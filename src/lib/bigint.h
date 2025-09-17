#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/******************************************************************************/

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s64 int64_t

#define MAX_BITS 4290000000

/* Get the i-th bit of BigInt n and store it in buffer identified by target.  */
/* Indexed from bit 0 onward. Little-endian byte order.                       */
#define BIGINT_GET_BIT(n, i, target)                                     \
target = (*((n).bits + (u32)(((i)-((i) % 8))/8)) & (1<<((i)%8))) ? 1 : 0 \

/* Change the printf() output color. */
void output_red(){ printf("\033[1;31m"); }
void output_yel(){ printf("\033[1;33m"); }
void output_rst(){ printf("\033[0m"); } 

typedef struct bigint{
    u8* bits;
    u32 size_bits;
    u32 used_bits;
    u32 free_bits;
} bigint;

/* First constructor - from a u32. */
void bigint_create(bigint* const num, const u32 bitsize, const u32 initial){

    if( (bitsize % 8) || (bitsize < 64) || (bitsize > MAX_BITS) ){
        printf("[ERR] Bigint: Invalid bitsize of new BigInt. (from uint32)\n");
        return;
    }    
    
    num->size_bits = bitsize;
    num->bits = (u8*)calloc(1, bitsize / 8);
    num->used_bits = 0;    
    
    for(u32 i = 0; i < 32; ++i){ /* most significant bit of u32 set. */
        if ( (initial << i) & (uint32_t)0x80000000 ){ 
            num->used_bits = 32 - i;  
            break;  
        }    
    }   
    
    num->free_bits = (bitsize - num->used_bits);
    
    for(u32 i = 0; i < 32; ++i){
        uint32_t* helper_ptr = (uint32_t*)(num->bits);
        if( initial & (1 << i) ){
             (*helper_ptr) |= 1 << i;
        }
    }    
}

void bigint_remake(bigint* const num, const u32 bitsize, const u32 initial){

    free(num->bits);

    bigint_create(num, bitsize, initial);

    return;
}

/* Place a BigInt's bits as ASCII characters into a given memory buffer. */
void bigint_get_ascii_bits( const bigint* const num 
                           ,char* const target_buffer)                   
{
    u32 bits_to_8 = num->used_bits;
    u32 bytes_used;
    
    while(bits_to_8 % 8){ 
        ++bits_to_8; 
    }
    
    bytes_used = bits_to_8 / 8;
    
    memset(target_buffer, 0, bytes_used * 8);          
             
    for(u32 i = 0; i < bytes_used; ++i){
        for(u8 j = 0; j < 8; ++j){
            if ((*((num->bits) + i ) >> (7 - j)) & 1){
                target_buffer[( (i * 8) + j )] = 49;
            }
            else{
                target_buffer[( (i * 8) + j )] = 48;
            }
        }
    }

    return;
}

/* Print only the used bits of a BigInt. */
void bigint_print_bits(const bigint* const n){

    u32 bits_to_8 = n->used_bits;
    u32 bytes_used;    

    char* bitstring;

    if( !(n->used_bits) ){
        printf("<ZERO>\n");
        return;
    }

    while(bits_to_8 % 8){ 
        ++bits_to_8; 
    }
    
    bytes_used = (u32)((double)bits_to_8 / (double)8.0);
     
    bitstring = (char*)calloc(1, (bytes_used * 8));

    bigint_get_ascii_bits(n, bitstring);
    
    printf("\n\n");

    for(u32 i = 0; i < bytes_used * 8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        if( (!(i % 32)) && (i) ){
            printf("\n | ");
        }
        printf("%c", bitstring[i]);
    }

    printf("\n\n");
    
    free(bitstring); 

    return; 
}

/* Print the big-endian version of the BigInt's bytes. */
void bigint_print_bits_bigend(const bigint* const n){

    u32 bits_to_8 = n->used_bits;
    u32 bytes_used;
            
    char* bitstring;
    char* bitstring_bigend;

    if( ! n->used_bits ){
        printf("<ZERO>\n");
        return;
    }
      
    while(bits_to_8 % 8){ 
        ++bits_to_8; 
    }
    
    bytes_used = (u32)((double)bits_to_8 / (double)8.0);
        
    bitstring        = (char*)calloc(1, bytes_used * 8);
    bitstring_bigend = (char*)calloc(1, bytes_used * 8);
    
    bigint_get_ascii_bits(n, bitstring);
    
    for(u32 i = 0; i < bytes_used; ++i){
        for(u32 j = 0; j < 8; ++j){
            bitstring_bigend[(8*i) + j] = bitstring[(8*(bytes_used - (i+1)))+j];
        }
    }
        
    printf("\n\n");

    for(u32 i = 0; i < bytes_used * 8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        if( !(i % 32) && (i) ){
            printf("\n | ");
        }
        printf("%c", bitstring_bigend[i]);
    }

    printf("\n\n");
    
    free(bitstring); 
    free(bitstring_bigend);

    return; 
}

/* Switch the endianness of a binary bit string. */
void bitstring_switch_endian( const char* const old_str
                             ,const u32         bytes_used
                             ,char* const       new_str)
{
    for(u32 i = 0; i < bytes_used; ++i){
        for(u32 j = 0; j < 8; ++j){
            new_str[(8 * (bytes_used - (i+1))) + j] = old_str[(8*i) + j];
        }
    } 

    return;   
}

/* Print all bits, including all unsued zeros, of a BigInt. */
void bigint_print_all_bits(bigint* const n){

    const u32 old_used_bits = n->used_bits;
    
    n->used_bits = n->size_bits;
    
    bigint_print_bits(n);
    
    n->used_bits = old_used_bits;
    
    return;
}

/* Print essential information about an existing BigInt. */
void bigint_print_info(const bigint* const num){

    printf("\n\n"
           "*******************************\n"
           "  BIGINT INFO                  \n"
           "                               \n"
           "  Bits size :  %u              \n"
           "  Used bits :  %u              \n"
           "  Free bits :  %u              \n"
           "*******************************\n\n"
           ,num->size_bits
           ,num->used_bits
           ,num->free_bits
    );

    return;
}

/* Given a buffer of bytes, get the index of the biggest ON bit. This would be
 * the "used_bits" count of a BigInt represented by this buffer.
 */
u32 get_used_bits(const u8* const buf, const u32 siz_bytes){

    u32 used_bits = siz_bytes * 8;
    
    /* Start from the rightmost byte, as this is biggest in little-endian. */
    for(int64_t i = siz_bytes - 1; i >= 0; --i){
        for(u8 j = 0; j < 8; ++j){  /* Examine each bit individually. */
            if(buf[i] & ( 1 << ( 7 - j))){
                return used_bits;
            }          
            --used_bits;
        }        
    }
    
    return used_bits;     
}

/* To view the bytes of the DAT files from linux terminal window: */
/* xxd -b G_raw_bytes.dat                                         */
bigint* get_bigint_from_dat( const u32    file_bits
                            ,const char* const fn
                            ,const u32    used_bits
                            ,const u32    reserve_bits)
{  
    bigint* big_n_ptr;
    FILE*   dat_file;
    u32     file_bytes;

    big_n_ptr = (bigint*)calloc(1, sizeof(bigint)); 
    bigint_create(big_n_ptr, reserve_bits, 0); 

    if(reserve_bits % 8 || reserve_bits < 64 || reserve_bits > MAX_BITS){ 
        printf("[ERR] BigInt: get_bigint_from_dat - Invalid reserve_bits\n");
        return big_n_ptr;
    }  
    
    if(reserve_bits < used_bits){
        printf("[ERR] BigInt: Too few reserved bits for .dat file: %s\n",fn);
        return big_n_ptr;
    }
    
    if ( (dat_file = fopen(fn, "r")) == NULL){
        printf("[ERR] BigInt: Could not open DAT file. File name: %s\n\n", fn);
        return big_n_ptr;
    }
    
    file_bytes = file_bits;

    while(file_bytes % 8 != 0){
        ++file_bytes;
    }

    file_bytes /= 8;
  
    big_n_ptr->used_bits = used_bits;
    big_n_ptr->free_bits = reserve_bits - used_bits;

    if(fread(big_n_ptr->bits, 1, file_bytes, dat_file) != file_bytes){
        printf("[ERR] BigInt: Could not read bigint DAT file: %s\n\n", fn);
    }
        
    if( fclose(dat_file) != 0){
        printf("[ERR] BigInt: Could not close bigint DAT file: %s\n\n", fn);
    }
    
    return big_n_ptr;
}

void save_bigint_to_dat(const char* const fn, const bigint* const num){  

    FILE* dat_file;
    u32   file_bytes;
    
    if ( (dat_file = fopen(fn, "w")) == NULL){
        printf("[ERR] BigInt: Could not open DAT file for writing:%s\n\n", fn);
        return;
    }
    
    file_bytes = num->used_bits;
    
    while(file_bytes % 8 != 0){
        ++file_bytes;
    }

    file_bytes /= 8;
        
    if( fwrite(num->bits, 1, file_bytes, dat_file) != file_bytes ){
        printf("[ERR] BigInt: Could not write bigint to DAT file: %s\n\n", fn);
    }
    
    if( fclose(dat_file) != 0){
        printf("[ERR] BigInt: Could not close DAT file for bigint:%s\n\n", fn);
    }
    
    return;
}

/* Make a BigInt equal to zero. */
void bigint_nullify(bigint* const num){

    memset(num->bits, 0, num->size_bits / 8);
    num->free_bits = num->size_bits;
    num->used_bits = 0;
    
    return;
}

/* Bitwise XOR operation of two BigInts n1 and n2. */
void bigint_xor2( const bigint* const n1
                 ,const bigint* const n2 
                 ,bigint* const res)
{
    u32 smaller;
    
    if (n1->size_bits > n2->size_bits){
        smaller = n2->size_bits;
    }
    else{
        smaller = n1->size_bits;
    }
    
    if(res->size_bits < smaller){
        printf("[ERR] BIGINT: Not enough bits to place the result of XOR.\n");
        return;
    }
    
    smaller /= 8;
    
    for(u32 i = 0; i < smaller; ++i){
        *(res->bits + i) = ( (*(n1->bits + i)) ^ (*(n2->bits + i)) ); 
    }
    
    return;
}

/* Bitwise AND operation of two BigInts n1 and n2. */
void bigint_and2( const bigint* const n1
                 ,const bigint* const n2
                 ,bigint* const res)
{
    u32 smaller;

    if (n1->size_bits > n2->size_bits){
        smaller = n2->size_bits;
    }
    else{
        smaller = n1->size_bits;
    }
    
    if(res->size_bits < smaller){
        printf("[ERR] BIGINT: Not enough bits for result of bitwise AND.\n");
        return;
    }
    
    smaller /= 8;
    
    for(u32 i = 0; i < smaller; ++i){
        *(res->bits + i) = ( (*(n1->bits + i)) & (*(n2->bits + i)) ); 
    }
    
    return;
}

/* Standard bitwise shift to the left of a BigInt by X bits. */
void bigint_shift_l_by_x(bigint* const n, const u32 amount){

    u32 used_bytes;
    
    if(amount >= n->size_bits){
        bigint_nullify(n);
        return;  
    }
    
    used_bytes = n->used_bits;

    while(used_bytes % 8 != 0){ 
        ++used_bytes; 
    }

    used_bytes /= 8;
      
    for(u32 x = 0; x < amount; ++x){
        for(int32_t i = used_bytes - 1; i >= 0; --i){

            *(n->bits + i) = *(n->bits + i) << 1; 

            if(  (i != 0)  &&  ((*(n->bits + i - 1) >> 7) & 1)  ){
                (*(n->bits + i)) |= 1;  
            }  
        } 
    } 
    
    return;
}

/* Standard bitwise shift to the right of a BigInt by X bits. */
void bigint_shift_r_by_x(bigint* const n, const u32 amount){

    u32 used_bytes;

    if(amount >= n->size_bits){
        bigint_nullify(n); 
        return;  
    }
    
    used_bytes = n->used_bits;

    while(used_bytes % 8 != 0){ 
        ++used_bytes; 
    }

    used_bytes /= 8;
      
    for(u32 x = 0; x < amount; ++x){
        for(u32 i = 0; i < used_bytes; ++i){

            *(n->bits + i) = *(n->bits + i) >> 1;

            if( (i != (used_bytes - 1)) && ((*(n->bits + i + 1)) & 1) ){ 
                (*(n->bits + i)) |= (1 << 7);   
            }
        } 
    } 
    
    return; 
}

/*   Compare two BigInts. Returns:
 *  
 *   1  if n1 > n2
 *   2  if n1 = n2
 *   3  if n1 < n2
 */
u8 bigint_compare2( const bigint* const n1, const bigint* const n2)
{
    u32 used_bytes;
    
    bool cond1;
    bool cond2;

    if(n1->used_bits > n2->used_bits){
        return 1; 
    }

    if(n1->used_bits < n2->used_bits){
        return 3;
    }

    used_bytes = n1->used_bits;

    while(used_bytes % 8 != 0){ 
        ++used_bytes; 
    }

    used_bytes /= 8;  
    
    for(int32_t i = (used_bytes - 1); i >= 0; --i){
        for(int32_t j = 0; j < 8; ++j){
        
            cond1 = ((*(n1->bits + i) << j) & (1 << 7));
            cond2 = ((*(n2->bits + i) << j) & (1 << 7));
            
            if( (cond1) && !(cond2) ){             
                return 1;            
            }

            else if( !(cond1) && (cond2) ){          
                return 3;            
            }

            else{ 
                continue; 
            }               
        }
    }
    
    return 2;  
}

/* Make BigInt n1 equal to the BigInt n2. */
void bigint_equate2(bigint* const n1, const bigint* const n2){

    u32 aux;

    if(n1->size_bits < n2->used_bits){ 
        printf("[ERR] Bigint: Equation target has too few reserved bits.\n");
        return;
    }
    
    if(!n2->used_bits){
        bigint_nullify(n1);
        return;
    }
    
    bigint_nullify(n1);
    
    aux = n2->used_bits;

    while(aux % 8 != 0) { 
        ++aux; 
    }

    aux /= 8;   

    n1->used_bits = n2->used_bits;
    n1->free_bits = n2->free_bits;
    
    for(u32 i = 0; i < aux; ++i){
        *(n1->bits + i) = *(n2->bits + i);
    }
    
    return;
}

/*  Standard addition of two BigInts.
 *
 *  WARNING: N1, N2 and R's reserved bits must be divisible by 32. 
 *           This will not be checked by the library for performance reasons.
 *
 *  R must have at least 32 more reserved bits than the bigger ADD operand's.
 */
void bigint_add_fast( const bigint* const n1
                     ,const bigint* const n2
                     ,bigint* const R)
{
    u64 A;
    u64 B;
    u64 C;
    u64 i = 0;
    u64 carry = 0;
    u64 temp_res = 0;
    u64 last_bits_bigger;
    
    u32* more_bits = NULL;

    uint32_t* aux_ptr_n1bits = (uint32_t*)(n1->bits);                          
    uint32_t* aux_ptr_n2bits = (uint32_t*)(n2->bits);                          
    uint32_t* aux_ptr_Rbits  = (uint32_t*)(R->bits); 

    bigint_nullify(R);
    
    if( n1->used_bits < n2->used_bits ){ 
        A = n2->used_bits;
        more_bits = (uint32_t*)(n2->bits);
    }

    else{ 
        A = n1->used_bits;
        more_bits = (uint32_t*)(n1->bits);
    }
    
    if(!n1->used_bits){
        bigint_equate2(R, n2);
        return;
    } 
    
    if(!n2->used_bits){
        bigint_equate2(R, n1);
        return;
    }
 
    C = A;
    B = A % 32;

    if(B) { 
        A += (32 - B); 
    }

    A /= 32;

    while(i < (A-1)){
    
        temp_res = 
            ( (u64)(aux_ptr_n1bits[i]) )
            +
            ( (u64)(aux_ptr_n2bits[i]) )
            +
            carry;
            ;

        carry = 0;
            
        if ( temp_res & (1ULL << 32LL) ){
            carry = 1;
        }
           
        aux_ptr_Rbits[i] = (u32)temp_res;
        
        ++i;
    }
    
    /* ---------------------------------------------------------------------- */

    temp_res =                                                               
        ( (u64)(aux_ptr_n1bits[i]) ) 
        +
        ( (u64)(aux_ptr_n2bits[i]) )
        +                                                                    
        carry;                                                               
        ;                    
 
    aux_ptr_Rbits[i] = (u32)temp_res;

    last_bits_bigger = 31;
    
    while( ! ( more_bits[i] & ( ((u32)1) << last_bits_bigger) ) ){
        --last_bits_bigger;
    }
 
    if ( temp_res & ((u64)1 << (last_bits_bigger + 1)) ){
    
            carry = 1;

            /*  Carry wasn't accounted for by built-in 
             *  addition because it was in the 33rd bit.
             */
            if(last_bits_bigger == 31){
                R->bits[((i+1) * 4)] |= 1;
            }
    }

    else{
        carry = 0;
    }    
    
    if(carry){ 
        R->used_bits = C + 1; 
    }

    else{ 
        R->used_bits = C; 
    }
    
    R->free_bits = R->size_bits - R->used_bits;
    
    return;
}

/* Standard multiplication of two BigInts. */
void bigint_mul_fast( const bigint* const n1
                     ,const bigint* const n2
                     ,bigint* const R)
{
    u64 A;
    u64 B;
    u64 AA;
    u64 BB;
    u64 C;
    u64 temp_res = 0;
    u64 i;
    u64 j;
    u64 bit_to_check;

    uint32_t* aux_ptr_tempres = (uint32_t*)(&temp_res);
    uint32_t* aux_ptr_n1bits  = (uint32_t*)(n1->bits);
    uint32_t* aux_ptr_n2bits  = (uint32_t*)(n2->bits);
    uint32_t* aux_ptr_Rbits   = (uint32_t*)(R->bits);

    bigint_nullify(R);
   
    if(R->size_bits < (n1->used_bits + n2->used_bits) ){
        printf("[ERR] Bigint: Not enough bits to store result of MUL.\n");
        return;       
    }
    
    if(!n1->used_bits || !n2->used_bits){ 
        return; 
    }
    
    if(n1->used_bits == 1){
        bigint_equate2(R, n2);
        return;
    } 
    
    if(n2->used_bits == 1){
        bigint_equate2(R, n1);
        return;
    }
    
    A  = n2->used_bits; 
    AA = n1->used_bits;
    
    B  = A % 32;   
    BB = AA % 32;
    
    if(B) { 
        A += (32 - B); 
    }  
    
    if(BB){ 
        AA+= (32 - BB); 
    }
    
    A  /= 32;
    AA /= 32;
       
    for(i = 0; i < A; ++i){

        C = 0;

        for(j = 0; j < AA; ++j){
            temp_res = 
                     ( (u64)(aux_ptr_Rbits[i+j]) )
                     +
                     C
                     +
                     (
                        ( (u64)(aux_ptr_n1bits[j]) ) 
                        * 
                        ( (u64)(aux_ptr_n2bits[i]) )
                     )
                     ;  
     
            /* 1st oldest version - gives warnings. Prefer 2nd version. */
            
            //((u32*)R->bits)[i+j] = *((u32*)(&temp_res));
            
            /* Third version, not with memcpy anymore, with proper pointers. */
            /* EXPERIMENTAL NEW -- Might not work. Check it. */            

            aux_ptr_Rbits[i+j] = *aux_ptr_tempres;
            
            /* Go (i+j) 32-bit places into R->bits. Place there temp_res. 
             * Replaces the commented line above to fix a GCC warning about
             * type-punned pointers being disallowed from being dereferenced. 
             *
             * <2nd version - OLD, working, no warnings. May need to bring back>
             */

            /*
            memcpy( ((void*)(&(((u32*)R->bits)[i + j])))
                   ,((void*)(&temp_res))
                   ,sizeof(u32)
                  );
            */

            C = (u64)(aux_ptr_tempres[1]);
        } 

        aux_ptr_Rbits[i + 1 + (AA - 1)] = aux_ptr_tempres[1];
    }

    R->used_bits = n1->used_bits + n2->used_bits;
    
    bit_to_check = n1->used_bits + n2->used_bits + 63 - ( (A + AA) * 32 ) ;
    
    if (!(temp_res & ((u64)1 << bit_to_check) )){
        --R->used_bits;    
    }
    
    R->free_bits = R->size_bits - R->used_bits;
    
    return;    
}

/* BigInt n1 to the power of BigInt n2. */
void bigint_pow( const bigint* const n1
                ,const bigint* const n2
                ,bigint* const R)
{
    bigint n1_used_bits;
    bigint R_req_bits;
    bigint zero;
    bigint one;
    bigint R_res_bits;
    bigint R_temp;
    bigint starter;
    bigint starter_temp;

    bigint_create(&R_temp,       n2->size_bits, 0);
    bigint_create(&starter,      n2->size_bits, 1);
    bigint_create(&starter_temp, n2->size_bits, 1);
    bigint_create(&zero,         n2->size_bits, 0);    
    bigint_create(&one,          n2->size_bits, 1);    
    bigint_create(&R_req_bits,   n2->size_bits, 0);
    bigint_create(&n1_used_bits, n2->size_bits, n1->used_bits);   
    bigint_create(&R_res_bits,   n2->size_bits, R->size_bits);

    bigint_nullify(R);
    
    if(n1->size_bits != n2->size_bits){
        printf("[ERR] Bigint: POW operands' reserved bits count must match.\n");
        goto ret_label;
    }
       
    if( bigint_compare2(n2, &zero) == 2){
        bigint_equate2(R, &one); 
        goto ret_label;  
    }
    
    if( bigint_compare2(n1, &zero) == 2){ 
        goto ret_label; 
    }
        
    if( bigint_compare2(n2, &one) == 2){
        bigint_equate2(R, n1); 
        goto ret_label;   
    }
               
    if( bigint_compare2(n1, &one) == 2){
        bigint_equate2(R, &one);
        goto ret_label;
    }

    bigint_mul_fast(&n1_used_bits, n2, &R_req_bits);
    
    if( bigint_compare2(&R_req_bits, &zero) == 2){
        printf("[ERR] BigInt: Bitlegnth of POW result exceeds max allowed.\n");
        goto ret_label;
    }
    
    if( bigint_compare2(&R_res_bits, &R_req_bits) == 3){
        printf("[ERR] BigInt: Not enough bits to store the result of POW.\n");
        printf("POW() operands:\nn1:\n");
        bigint_print_info(n1);
        bigint_print_bits(n1);
        printf("\nn2:\n");
        bigint_print_info(n2);
        bigint_print_bits(n2);
        printf("R_res_bits:\n");
        bigint_print_info(&R_res_bits);
        bigint_print_bits(&R_res_bits);
        printf("R_req_bits:\n");
        bigint_print_info(&R_req_bits);
        bigint_print_bits(&R_req_bits);
        goto ret_label;    
    }
     
    bigint_equate2(R, n1);

    while( bigint_compare2(&starter, n2) == 3){
        bigint_equate2(&R_temp, R);
        bigint_equate2(&starter_temp, &starter);
        bigint_add_fast(&starter_temp, &one, &starter);
        bigint_mul_fast(&R_temp, n1, R); 
    } 
    
ret_label:
    free(n1_used_bits.bits);
    free(R_req_bits.bits);
    free(zero.bits); 
    free(one.bits);
    free(R_res_bits.bits); 
    free(R_temp.bits); 
    free(starter.bits); 
    free(starter_temp.bits);
        
    return;
}

/* Standard subtraction of two BigInts. R = n1 - n2. */
void bigint_sub2( const bigint* const n1
                 ,const bigint* const n2
                 ,bigint* const R)
{

    u32 bigger_used_bytes;
    u32 bit_counter1 = 0;
    u32 bit_counter2 = 0;
    u32 old_i = 0;
    u32 old_j = 0;
            
    u8 borrowing = 0;
    
    bigint zero;
    bigint n1_copy;   

    bigint_create(&zero, n2->size_bits, 0);   
    bigint_create(&n1_copy, n1->size_bits, 0);

    bigint_nullify(R);
    
    if( bigint_compare2(n1, n2) == 3){
        printf("[ERR] Bigint: n1 was smaller than n2 in a SUB operation.\n"); 
        goto label_ret;  
    }
    
    if( bigint_compare2(n1, n2) == 2){ 
        goto label_ret;
    }
    
    if( bigint_compare2(n2, &zero) == 2){
        bigint_equate2(R, n1); 
        goto label_ret;  
    }
    
    if(n2->size_bits < n1->used_bits){
        printf("[ERR] Bigint: n2 in SUB doesn't have enough reserved bits.\n");
        goto label_ret;
    }
    
    if(R->size_bits < n1->used_bits){
        printf("[ERR] Bigint: SUB result has insufficient reserved bits.\n");
        goto label_ret;
    }
    
    bigint_equate2(&n1_copy, n1);

    bigger_used_bytes = n1->used_bits; 

    while(bigger_used_bytes % 8 != 0){ 
        ++bigger_used_bytes; 
    }
    
    bigger_used_bytes /= 8;
     
    for(u32 i = 0; i < bigger_used_bytes; ++i){
        for(u32 j = 0; j < 8; ++j){

            if(borrowing){
                if( !( ((*(n1_copy.bits + i)) >> j) & 1 ) ){
                    (*(n1_copy.bits + i)) |= 1 << j;
                    continue;    
                }
                else{
                    (*(n1_copy.bits + i)) ^= 1 << j; 
                    i = old_i;
                    j = old_j;
                    borrowing = 0;
                    continue;                   
                }              
            }

            ++bit_counter1;
            
            if(     
                  ( ((*(n1_copy.bits + i)) >> j) & 1 )  
               && ( ((*(n2->bits + i)) >> j) & 1 )  
              )
            {
                continue;
            }
              
            else if(    
                         ( ((*(n1_copy.bits + i)) >> j) & 1 )  
                     && !( ((*(n2->bits + i)) >> j) & 1 )  
                   )
            {
                (*(R->bits + i)) |= 1 << j;
                bit_counter2 = bit_counter1;
                continue;                           
            }
                   
            else if(
                        !( ((*(n1_copy.bits + i)) >> j) & 1 )  
                     &&  ( ((*(n2->bits + i)) >> j) & 1 )   
                   )
            {
                (*(R->bits + i)) |= 1 << j;
                bit_counter2 = bit_counter1;                     
                borrowing = 1;
                old_i = i;
                old_j = j;
                continue;                     
            }
                   
            else{ 
                continue; 
            }
        }
    }    
    
    R->used_bits = bit_counter2;  
    R->free_bits = R->size_bits - R->used_bits;
    
label_ret:
    free(zero.bits);
    free(n1_copy.bits);
    
    return;    
}

/* Implementation of Algorithm 20.4 "Multiple Precision Division" in Handbook of
 * Applied Cryptography. Using 16-bit limbs so that u64 storage is sufficient. 
 */        
void bigint_div2( const bigint* const A
                 ,const bigint* const B
                 ,bigint* const Res
                 ,bigint* const Rem)
{      
    const u64 num_temps = 19; /* How many temporary BigInts we need. */
    
    u64 b = (u64)pow(2,16);
    u64 b_squared = b*b;
    u64 n;
    u64 t;
    u64 i;
    
    bigint big_temps[num_temps];
    
    for(i = 0; i < num_temps; ++i){
        bigint_create(&(big_temps[i]), A->size_bits, 0);
    }

    /* Quickly check if A or B are zero. */
    if(bigint_compare2(B, &(big_temps[0])) == 2){
        printf("\n\n[ERR] BIGINT - Division by ZERO.\n\nOPERAND 1:\n");
        bigint_print_info(A);
        bigint_print_bits(A);
        goto label_cleanup;
    }
    
    if(bigint_compare2(A, &(big_temps[0])) == 2){
        bigint_nullify(Res);
        bigint_nullify(Rem);
        goto label_cleanup;
    }
    
    /* if B > A, return RES=0, REM=A  */
    if(bigint_compare2(A, B) == 3){
        bigint_nullify(Res);
        bigint_equate2(Rem, A);
        goto label_cleanup;
    }

    bigint_equate2(&(big_temps[0]), A);
    bigint_equate2(&(big_temps[2]), B);

    n = big_temps[0].used_bits;

    while(n % 16){
        ++n;        
    } 

    n /= 16;
    --n;
    
    t = big_temps[2].used_bits;

    while(t % 16){
        ++t;
    }

    t /= 16;
    --t;

    /* Initialize the bigints that will stay constant during the algorithm. */
    bigint_remake(&(big_temps[5]),  A->size_bits, (u32)1);
    bigint_remake(&(big_temps[6]),  A->size_bits, (u32)b);
    bigint_remake(&(big_temps[7]),  A->size_bits, (u32)n);
    bigint_remake(&(big_temps[8]),  A->size_bits, (u32)t);
    bigint_remake(&(big_temps[10]), A->size_bits, (u32)(n-t));

    bigint_pow(&(big_temps[6]), &(big_temps[10]), &(big_temps[11]));

    bigint_mul_fast(&(big_temps[11]), &(big_temps[2]), &(big_temps[12]));
    
    /**** ============= HELPER POINTER DECLARATIONS START =================== */

    /* IMPORTANT NOTE: The algorithm REMAKES big_temps [17] and [9].
     *                 This means a new bits pointer returned by calloc
     *                 in the bigint_create() in REMAKE. So, if they exist,
     *                 update any auxilliary different-type pointers to
     *                 to their bits buffer (equalling .bits ptr struct field)!
     */

    uint16_t* aux_ptr16_temp3bits = (uint16_t*)(big_temps[3].bits);
    uint16_t* aux_ptr16_temp0bits = (uint16_t*)(big_temps[0].bits);
    uint16_t* aux_ptr16_temp2bits = (uint16_t*)(big_temps[2].bits);

    /**** ============= HELPER POINTER DECLARATIONS END   =================== */

    /* Part 2 */
    while(bigint_compare2(&(big_temps[0]), &(big_temps[12])) != 3){
        aux_ptr16_temp3bits[n-t] += 1;
        bigint_equate2(&(big_temps[1]), &(big_temps[0]));
        bigint_sub2(&(big_temps[1]), &(big_temps[12]), &(big_temps[0]));
    }
    
    /* Part 3 */
    for(i = n; i >= (t+1); --i){
         
        if(aux_ptr16_temp0bits[i] == aux_ptr16_temp2bits[t]) 
        {
            /* q_(i-t-1) a limb, also stored as a bigint in big_temps[17]. */ 
            aux_ptr16_temp3bits[i-t-1] = (uint16_t)(b - 1);
            
            bigint_remake(&(big_temps[17]), A->size_bits, (u32)(b - 1));
        }
        else{
             aux_ptr16_temp3bits[i-t-1] = 
              (u16)floor(
                  ( (((u64)(aux_ptr16_temp0bits[i])) * b )
                    + (u64)(aux_ptr16_temp0bits[i-1]) 
                  )
                  / ( (u64)(aux_ptr16_temp2bits[t]) )
              );
        }
        
        while(
              (  ( (((u64)(aux_ptr16_temp2bits[t])) * b )
                   + (u64)(aux_ptr16_temp2bits[t-1])
                 )
                 * ( (u64)(aux_ptr16_temp3bits[i-t-1]) ) 
              )
              > 
              ( ( ((u64)(aux_ptr16_temp0bits[i])) * b_squared )
                  + ( ((u64)(aux_ptr16_temp0bits[i-1]))  * b) 
                  + (  (u64)(aux_ptr16_temp0bits[i-2]))
              )
        )
        {
           aux_ptr16_temp3bits[i-t-1] -= 1;
        }
        
        /* IMPORTANT: Update X's bits before this, as its limbs were altered.
         * 
         * if( x < q_(i-t-1) * y * b^(i-t-1 ) ) THEN {q_(i-t-1) -= 1;}
         * 
         * x -= q_(i-t-1) * y * b^(i-t-1) ;
         */
        big_temps[0].used_bits = get_used_bits( big_temps[0].bits,
                                                (u32)((A->size_bits)/8)
                                              );
                                              
        big_temps[0].free_bits = A->size_bits - big_temps[0].used_bits; 
        
        bigint_remake(&(big_temps[9]), A->size_bits, (u32)i);

        bigint_sub2(&(big_temps[ 9]), &(big_temps[8]), &(big_temps[13]));

        bigint_sub2(&(big_temps[13]), &(big_temps[5]), &(big_temps[14]));

        bigint_pow(&(big_temps[6]), &(big_temps[14]), &(big_temps[15]));

        bigint_mul_fast(&(big_temps[2]), &(big_temps[15]), &(big_temps[16]));
        
        bigint_remake(&(big_temps[17])
                     ,A->size_bits
                     ,(u32)(aux_ptr16_temp3bits[i-t-1])
                     );
                     
        bigint_mul_fast(&(big_temps[16]), &(big_temps[17]), &(big_temps[18]));
        
        if(bigint_compare2(&(big_temps[0]), &(big_temps[18])) == 3){
        
            aux_ptr16_temp3bits[i-t-1] -= 1;
           
            bigint_remake(&(big_temps[17])
                         ,A->size_bits
                         ,(u32)(aux_ptr16_temp3bits[i-t-1])
                         );
            
            bigint_mul_fast
               (&(big_temps[16]), &(big_temps[17]), &(big_temps[18]));
        }
        
        bigint_equate2(&(big_temps[1]), &(big_temps[0]));

        bigint_sub2(&(big_temps[1]), &(big_temps[18]), &(big_temps[0])); 
    }
    
    big_temps[0].used_bits = get_used_bits( big_temps[0].bits,
                                            (u32)((A->size_bits)/8)
                                          );
                                          
    big_temps[0].free_bits = A->size_bits - big_temps[0].used_bits; 
    
    big_temps[3].used_bits = get_used_bits( big_temps[3].bits,
                                            (u32)((A->size_bits)/8) 
                                          );
                                          
    big_temps[3].free_bits = A->size_bits - big_temps[3].used_bits; 
    
    bigint_equate2(Rem, &(big_temps[0]));
    bigint_equate2(Res, &(big_temps[3]));

label_cleanup:

    for(i = 0; i < num_temps; ++i){
        free(big_temps[i].bits);
    }
    
    return;
}

/* Modular Multiplication. Multiply many BigInts, modulo another BigInt. */
void bigint_mod_mul( bigint** nums
                    ,const bigint*  const mod 
                    ,const u32 how_many
                    ,bigint* const R)
{
    bigint div_res;
    bigint rem;
    bigint mul_res;
                 
    u8 compare_res;

    bigint_create(&div_res, nums[0]->size_bits, 1);
    bigint_create(&mul_res, nums[0]->size_bits, 1);
    bigint_create(&rem,     nums[0]->size_bits, 1);

    bigint_equate2(R, &rem); 
    
    if(how_many < 2) {
        printf("[ERR] BigInt: ModMUL - fewer than 2 BigInts were supplied.\n");
        goto label_ret;
    }
    
    compare_res = 0;

    /* The long loop */
    for(u32 i = 0; i < how_many; ++i){
        /*
        printf("[BigInt] - Long loop in MOD_MUL moved  i = %u to %u"
              " (how many big numbers we multiply).\n"
              , i, how_many
              ); 
        */      
        bigint_mul_fast(R, nums[i], &mul_res);

        if( (compare_res = bigint_compare2(&mul_res, mod)) != 3){
            bigint_div2(&mul_res, mod, &div_res, &rem);                                   
            bigint_equate2(R, &rem);
        }
        else{
            bigint_equate2(R, &mul_res);
        }   
    }
    
label_ret:
    free(mul_res.bits);
    free(div_res.bits);
    free(rem.bits);
    
    return;
}  

/* Modular powering. BigInt_N to the power of BigInt_P, modulo BigInt_M. */
void bigint_mod_pow( const bigint* const N
                    ,const bigint* const P
                    ,const bigint* const M
                    ,bigint* const R)
{
    bigint   aux1;
    bigint   aux2;
    bigint   two;
    bigint   div_res;
    bigint   one;
    bigint   zero;
    bigint*  arr2     = NULL;
    bigint** arr_ptrs = NULL;
        
    u32* arr1 = NULL;
    u32  c1 = 0;
    u32  P_used_bytes = P->used_bits;
    u32  arr1_curr_ind = 0;

    arr1 = (u32*)calloc(1, P->used_bits * (sizeof(u32)));

    while(P_used_bytes % 8) { 
        ++P_used_bytes; 
    }

    P_used_bytes /= 8;

    for(u32 i = 0; i < P_used_bytes; ++i){
        for(u32 j = 0; j < 8; ++j){
            if( ( (*(P->bits + i)) >> j) & 1){
                arr1[arr1_curr_ind] = (i * 8) + j;
                ++arr1_curr_ind;
                ++c1;
            }     
        }
    }

    bigint_nullify(R);

    bigint_create(&aux1,    M->size_bits, 1);
    bigint_create(&aux2,    M->size_bits, 1);
    bigint_create(&two,     M->size_bits, 2);
    bigint_create(&one,     M->size_bits, 1);
    bigint_create(&zero,    M->size_bits, 0);
    bigint_create(&div_res, M->size_bits, 1);

    arr2     = (bigint*) calloc(1, c1 * sizeof(bigint));
    arr_ptrs = (bigint**)calloc(1, c1 * sizeof(bigint*));

    for(u32 i = 0; i < c1; ++i){
        bigint_create(&(arr2[i]), M->size_bits, 1); 
        arr_ptrs[i] = &arr2[i];
    }

    if(R->size_bits < M->used_bits){
        printf("[ERR] BigInt: Mod_Pow - too few reserved bits in Result.\n");
        goto label_ret;
    }
    
    if( !(M->size_bits > (2 * M->used_bits)) ){
        printf("[ERR] BigInt: Mod_Pow: wrong M's reserved bits.\n");
        goto label_ret;
    }
    
    if(bigint_compare2(M, &zero) == 2){
        printf("[ERR] BigInt: Mod_Pow: Division by zero.\n");
        goto label_ret;
    }
    
    if(bigint_compare2(M, &one) == 2){ 
        goto label_ret; 
    }
    
    if(bigint_compare2(P, &zero) == 2){
        bigint_equate2(R, &one);
        goto label_ret;
    }

    if(bigint_compare2(P, &one) == 2){
        bigint_div2(N, M, &div_res, R);
        goto label_ret;
    }
    if(bigint_compare2(N, &zero) == 2){ 
        goto label_ret; 
    }
    
    if(bigint_compare2(N, &one) == 2){
        bigint_equate2(R, &one);
        goto label_ret;
    }

    arr1_curr_ind = 0;  

    bigint_div2(N, M, &div_res, &aux1);

    /* The long loop */
    for(u32 i = 0; i < P->used_bits; ++i){   

        /*
        printf("[BigInt] - Long loop in MOD_POW moved  i = %u to %u"
               " (power's used bits).\n"
               , i, P->used_bits
               ); 
        */

        if( i == arr1[arr1_curr_ind] ){
            bigint_equate2( arr_ptrs[arr1_curr_ind], &aux1);
            ++arr1_curr_ind;
        }

        bigint_pow(&aux1, &two, &aux2);
        bigint_div2(&aux2, M, &div_res, &aux1);  
    }  

    if(c1 == 1){
        bigint_equate2(R, arr_ptrs[0]);
        goto label_ret;
    }

    bigint_mod_mul(arr_ptrs, M, c1, R);
label_ret:

    for(u32 i = 0; i < c1; ++i){
        free(arr2[i].bits);
    }  

    free(arr2);
    free(arr_ptrs);  
    free(arr1); 
    free(aux1.bits);
    free(aux2.bits);
    free(div_res.bits);
    free(zero.bits);
    free(one.bits);
    free(two.bits);

    return;
}

/* Fast algorithm for determining whether a BigInt is prime or not. */
/* Returns 1 if the big number is prime, or 0 otherwise. */
u8 rabin_miller(const bigint* const N, const u32 passes){
    
    bigint  N_minus_one;
    bigint  zero;
    bigint  one;
    bigint  two;
    bigint  M;
    bigint  B0;
    bigint  Bi_prev;
    bigint  Bi;
    bigint  div_res;
    bigint  rem;
    bigint  aux1;
    bigint* As;
    
    u32 K = 0;
    u32 A_val = 2;
    u32 curr_A_ind = 0;
    u32 prime_votes = 0;
    
    u8 K_flag = 1;
    u8 ret = 0;
    u8 lab_b0_flag = 0;
    u8 lab_ret_flag = 0;
    
    bigint_create(&N_minus_one, N->size_bits, 0);
    bigint_create(&one,         N->size_bits, 1);
    bigint_create(&two,         N->size_bits, 2);   
    bigint_create(&M,           N->size_bits, 0);
    bigint_create(&B0,          N->size_bits, 0);
    bigint_create(&Bi_prev,     N->size_bits, 0);
    bigint_create(&Bi,          N->size_bits, 0);
    bigint_create(&div_res,     N->size_bits, 0);
    bigint_create(&rem,         N->size_bits, 0);
    bigint_create(&zero,        N->size_bits, 0);
    bigint_create(&aux1,        N->size_bits, 0);    

    bigint_sub2(N, &one, &N_minus_one);
      
    /* Get K and M */
    bigint_equate2(&aux1, &N_minus_one);
    
    while(K_flag){
            
        bigint_div2(&aux1, &two, &div_res, &rem);
       
        if(bigint_compare2(&rem, &zero) == 2){
            ++K;
            bigint_equate2(&aux1, &div_res);
            bigint_equate2(&M, &div_res);
        }
        else{
            K_flag = 0;
        }
    }
    
    /* Create the different A's we will use */
    As = (bigint*)calloc(1, ( (passes * 2) + 1) * sizeof(bigint));
    
    for(u32 i = 0; i < (passes * 2) + 1; ++i){
        bigint_create(&(As[i]), N->size_bits, A_val);
        ++A_val;
    }

label_B0:
    lab_b0_flag = 0;

    /* Compute this A's b0 */
    bigint_mod_pow(&(As[curr_A_ind]), &M, N, &B0);

    if( 
          (bigint_compare2(&B0, &one) == 2) 
       || (bigint_compare2(&B0, &N_minus_one) == 2) 
      )
    {
        ++prime_votes;
        
        if(prime_votes == passes){
            ret = 1;
            goto label_ret;    
        }
        else{
            ++curr_A_ind;
            goto label_B0;
        }    
    }
    
    /* Start computing this A's Bi terms till the B(K-1)-th term. */
    else{
        bigint_equate2(&Bi, &B0);
        
        for(u32 i = 1; i < K; ++i){
        
            bigint_equate2(&Bi_prev, &Bi);
            bigint_mod_pow(&Bi_prev, &two, N, &Bi);
            
            if(bigint_compare2(&Bi, &N_minus_one) == 2){
            
                ++prime_votes; 
                
                if(prime_votes == passes){
                    ret = 1;
                    lab_ret_flag = 1;
                    break;    
                }
                else{
                    ++curr_A_ind;
                    lab_b0_flag = 1;
                    break;
                }     
            } 
              
            if( (i == (K - 1)) ){
                lab_ret_flag = 1;
                break;    
            }
        }
        
        if(lab_ret_flag) { 
            goto label_ret; 
        }
        
        if(lab_b0_flag)  { 
            goto label_B0;  
        }
    }
    
label_ret:

    free(N_minus_one.bits);
    free(one.bits);
    free(two.bits);
    free(M.bits);
    free(B0.bits);
    free(Bi_prev.bits);
    free(Bi.bits);
    free(div_res.bits);
    free(rem.bits);
    free(zero.bits);
    free(aux1.bits);
    
    for(u32 i = 0; i < (passes * 2) + 1; ++i){
        free(As[i].bits);
    }
    
    free(As);
    
    return ret;
 }
