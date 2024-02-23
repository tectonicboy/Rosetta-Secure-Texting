#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>

#define MAX_BITS 4290000000

void output_red(){ printf("\033[1;31m"); }
void output_yel(){ printf("\033[1;33m"); }
void output_rst(){ printf("\033[0m"); } 

struct bigint{
    uint8_t* bits;
    uint32_t size_bits;
    uint32_t used_bits;
    uint32_t free_bits;
};

/* First constructor - from a uint32_t. */
void bigint_create (struct bigint* num, uint32_t bitsize, uint32_t initial){
    if( (bitsize % 0x08) || (bitsize < 0x40) || (bitsize > MAX_BITS) ){
        printf("[ERR] Bigint: Invalid bitlength L of new big int. (from uint32)\n");
        return;
    }    
    num->size_bits = bitsize;
    num->bits = calloc(1, bitsize / 0x08);

    num->used_bits = 0x00;    
    for(uint32_t i = 0x00; i < 0x20; ++i){
        if ( (initial << i) & 0x80000000 ){ 
            num->used_bits = 0x20 - i;  
            break;  
        }    
    }   
    num->free_bits = (bitsize - num->used_bits);
    
    for(uint32_t i = 0x00; i < 0x20; ++i){
        if ( (initial >> (32 - i) & 0x01 )){ 
            ( *((uint32_t*)(num->bits) )) |=  0x01 << (32 - i);
        }
    } 
}

/* Second constructor - from a binary string. Little-endian assumed. */
void bigint_create_from_string (struct bigint* num, uint32_t bitsize
                               ,char* initial, uint32_t strlen)
                               {
    if( 
        (bitsize % 0x08) || (bitsize < 0x40) || (bitsize > MAX_BITS) 
                         || (strlen % 0x08  || strlen < 0x40)
      )
    {
        printf("[ERR] Bigint: Invalid bitlength L of new big int. (from string)\n");
        return;
    }
    if(bitsize < strlen){
        printf("[ERR] Bigint: Initializer bit string is longer than requested in constructor.\n");
        return;
    }
    
    num->size_bits = bitsize;
    num->bits = calloc(0x01, bitsize / 0x08);    
    
    uint32_t bitcounter = 0;
    uint8_t breakflag = 0;
    
    for(int32_t i = (strlen / 8) - 1; i >= 0; --i){
        for(uint32_t j = 0; j < 8; ++j){
            if(initial[(i*8) + j] == '1'){
                breakflag = 1;
                break;
            }
            ++bitcounter;
        }
        if(breakflag){break;}
    } 
    
    num->used_bits = strlen - bitcounter;
    
    uint32_t last_byte_i = strlen - 8;
    
    while(initial[last_byte_i] == '0'){
        ++last_byte_i;
    }
        
    uint32_t i_looper = strlen / 8;
    
    for(uint32_t i = 0; i < i_looper; ++i){
        for(uint32_t j = 0x00; j < 0x08; ++j){
            if ( initial[ (i*8) + j] == '1' ){ 
                *(num->bits + i) |= 0x01 << (0x07 - j);  
            }     
        }
    }   
    
    num->free_bits = (bitsize - num->used_bits);
}

/* Place a BigInt's bits as ASCII characters into a given memory buffer. */
void bigint_get_ascii_bits (struct bigint* num, char* target_buffer){
  
    uint32_t bits_to_8 = num->used_bits
            ,bytes_used;
    
    while(bits_to_8 % 8){ 
        ++bits_to_8; 
    }
    
    bytes_used = bits_to_8 / 8;
    
    memset(target_buffer, 0x00, bytes_used * 8);          
             
    for(uint32_t i = 0x00; i < bytes_used; ++i){
        for(uint8_t j = 0x00; j < 0x08; ++j){
            if ((*((num->bits) + i ) >> (7 - j)) & 0x01){
                target_buffer[( (i * 0x08) + j )] = 0x31;
            }
            else{
                target_buffer[( (i * 0x08) + j )] = 0x30;
            }
        }
    }
}

/* Print only the used bits of a BigInt. */
void bigint_print_bits(struct bigint* n){

    if( ! n->used_bits ){
        printf("<ZERO>\n");
        return;
    }
    
    uint32_t bits_to_8 = n->used_bits
            ,bytes_used;
    
    while(bits_to_8 % 8){ ++bits_to_8; }
    
    bytes_used = bits_to_8 / 8;
        
    char* bitstring = malloc(bytes_used * 8);
    
    bigint_get_ascii_bits(n, bitstring);
    
    printf("\n\n");
    for(uint32_t i = 0; i < bytes_used*8; ++i){
        if( !(i % 8) ){
            printf(" | ");
        }
        if( !(i % 32) && (i) ){
            printf("\n | ");
        }
        printf("%c", bitstring[i]);
    }
    printf("\n\n");
    
    free(bitstring); 
    return; 
}

/* Print the big-endian version of the BigInt's bytes. */
void bigint_print_bits_bigend(struct bigint* n){

    if( ! n->used_bits ){
        printf("<ZERO>\n");
        return;
    }
    
    uint32_t bits_to_8 = n->used_bits
            ,bytes_used;
    
    while(bits_to_8 % 8){ ++bits_to_8; }
    
    bytes_used = bits_to_8 / 8;
        
    char* bitstring = malloc(bytes_used * 8);
    char* bitstring_bigend = malloc(bytes_used * 8);
    
    bigint_get_ascii_bits(n, bitstring);
    
    for(uint32_t i = 0; i < bytes_used; ++i){
        for(uint32_t j = 0; j < 8; ++j){
            bitstring_bigend[(8*i) + j] = bitstring[(8 * (bytes_used - (i+1))) + j];
        }
    }
        
    printf("\n\n");
    for(uint32_t i = 0; i < bytes_used * 8; ++i){
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
void bitstring_switch_endian(char* old_str, uint32_t bytes_used, char* new_str){
    for(uint32_t i = 0; i < bytes_used; ++i){
        for(uint32_t j = 0; j < 8; ++j){
            new_str[(8 * (bytes_used - (i+1))) + j] = old_str[(8*i) + j];
        }
    } 
    return;   
}

/* Print all bits, including all unsued zeros, of a BigInt. */
void bigint_print_all_bits(struct bigint* n){
    uint32_t old_used_bits = n->used_bits;
    n->used_bits = n->size_bits;
    bigint_print_bits(n);
    n->used_bits = old_used_bits;
    return;
}

/* Print essential information about an existing BigInt. */
void bigint_print_info(struct bigint* num){
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
}

/* Given a buffer of bytes, get the index of the biggest ON bit. This would be
 * the "used_bits" count of a BigInt represented by this buffer.
 */
uint32_t get_used_bits(uint8_t* buf, uint32_t siz_bytes){
	uint32_t used_bits = siz_bytes * 8;
	/* Start from the rightmost byte, as this is biggest in little-endian. */
	for(int64_t i = siz_bytes - 1; i >= 0; --i){
		/* Examine each byte individually. */
		for(uint8_t j = 0; j < 8; ++j){
			if(buf[i] & ( 1 << ( 7 - j))){
				return used_bits;
			}  		
			--used_bits;
		}		
	}
	return used_bits; 	
}

/* Get the i-th bit of BigInt n and store it in buffer identified by target. */
/* Indexed from bit 0 onward. Little-endian bytes.						     */
#define BIGINT_GET_BIT(n, i, target)										   \
target = (*((n).bits + (uint32_t)(((i)-((i) % 8))/8)) & (1<<((i)%8))) ? 1 : 0 \

/* To view the bytes of the DAT files from linux terminal window: */
/* xxd -b G_raw_bytes.dat                                         */
struct bigint* get_BIGINT_from_DAT(uint32_t file_bits, char* fn, 
								   uint32_t used_bits, uint32_t reserve_bits)
{  
    if(reserve_bits % 0x08 || reserve_bits < 0x40 || reserve_bits > 4290000000){ 
        printf("[ERR] Cryptolib: get_BIGINT_from_DAT - Invalid reserve_bits\n");
        return NULL;
    }  
    if(reserve_bits < used_bits){
        printf("[ERR] Cryptolib: Too few reserved bits for .dat file: %s\n",fn);
        return NULL;
    }
    
    FILE* dat_file;
    if ( (dat_file = fopen(fn, "r")) == NULL){
        printf("[ERR] Cryptolib: Opening .dat file failed. Returning NULL.\n");
        return NULL;
    }
    
    uint32_t file_bytes = file_bits;
    while(file_bytes % 8 != 0){
        ++file_bytes;
    }
    file_bytes /= 8;
    
    char* bigint_buf = calloc(1, (size_t)(reserve_bits / 8));
    
    if(!fread(bigint_buf, 1, file_bytes, dat_file)){
    	printf("[WARN] Cryptolib: No bytes read from bigint file %s\n", fn);
    }
    
    struct bigint* big_n_ptr = calloc(1, sizeof(struct bigint)); 
    bigint_create(big_n_ptr, reserve_bits, 0);  
    memcpy(big_n_ptr->bits, bigint_buf, file_bytes);  
    big_n_ptr->used_bits = used_bits;
    big_n_ptr->free_bits = reserve_bits - used_bits;
    
    free(bigint_buf);
    
    if( fclose(dat_file) != 0){
    	printf("[ERR] Cryptolib: fclose() in READ failed for file: %s\n", fn);
    }
    
    return big_n_ptr;
}

void save_BIGINT_to_DAT(char* fn, struct bigint* num){  

    FILE* dat_file;
    size_t bytes_written;
    if ( (dat_file = fopen(fn, "w")) == NULL){
        printf("[ERR] Cryptolib: Opening .dat file failed in SAVE.\n");
        return;
    }
    
    uint32_t file_bytes = num->used_bits;
    
    while(file_bytes % 8 != 0){
        ++file_bytes;
    }
    file_bytes /= 8;
        
    if(! (bytes_written = fwrite(num->bits, 1, file_bytes, dat_file)) ){
    	printf("[WARN] Cryptolib: No bytes written to bigint dat file.\n");
    }
    
    printf("Written %lu bytes to bigint file %s\n", bytes_written, fn);
    
    if( fclose(dat_file) != 0){
    	printf("[ERR] Cryptolib: fclose() in SAVE failed for file %s\n", fn);
    }
    
    return;
}

/* Make a BigInt equal to zero. */
void bigint_nullify(struct bigint* num){
    memset(num->bits, 0x00, num->size_bits/8);
    num->free_bits = num->size_bits;
    num->used_bits = 0;
}

/* Bitwise XOR operation of two BigInts n1 and n2. */
void bigint_XOR2 (struct bigint* n1, struct bigint* n2, struct bigint* res){
    uint32_t smaller;

    if (n1->size_bits > n2->size_bits){
        smaller = n2->size_bits;
    }
    else{
        smaller = n1->size_bits;
    }
    if(res->size_bits < smaller){
        printf("[ERR] BIGINT: Not enough bits to place the result of XOR in.\n");
        return;
    }
    for(uint32_t i = 0; i < (smaller/8); ++i){
        *(res->bits + i) = ( (*(n1->bits + i)) ^ (*(n2->bits + i)) ); 
    }
}

/* Bitwise AND operation of two BigInts n1 and n2. */
void bigint_AND2 (struct bigint* n1, struct bigint* n2, struct bigint* res){
    uint32_t smaller;

    if (n1->size_bits > n2->size_bits){
        smaller = n2->size_bits;
    }
    else{
        smaller = n1->size_bits;
    }
    if(res->size_bits < smaller){
        printf("[ERR] BIGINT: Not enough bits to place the result of AND in.\n");
        return;
    }
    for(uint32_t i = 0; i < (smaller/8); ++i){
        *(res->bits + i) = ( (*(n1->bits + i)) & (*(n2->bits + i)) ); 
    }
}

/* Standard bitwise shift to the left of a BigInt by X bits. */
void bigint_SHIFT_L_by_X(struct bigint* n, uint32_t amount){

    if(amount >= n->size_bits){
        for(uint32_t i = 0; i < (n->size_bits / 8); ++i){
            *(n->bits + i) = 0;
        }  
        return;  
    }
    
    uint32_t used_bytes = n->used_bits;
    
    while(used_bytes % 0x08 != 0x00){ ++used_bytes; }
    
    used_bytes /= 0x08;
      
    for(uint32_t x = 0x00; x < amount; ++x){
        for(int32_t i = used_bytes - 1; i >= 0; --i){
            *(n->bits + i) = *(n->bits + i) << 0x01; 
            if(i != 0x00){
                if( (*(n->bits + i - 0x01) >> 0x07) & 0x01){             
                    (*(n->bits + i)) |= 0x01;   
                }   
            }  
        } 
    }  
}

/* Standard bitwise shift to the right of a BigInt by X bits. */
void bigint_SHIFT_R_by_X(struct bigint* n, uint32_t amount){

    if(amount >= n->size_bits){
        for(uint32_t i = 0x00; i < (n->size_bits / 0x08); ++i){
            *(n->bits + i) = 0x00;
        }  
        return;  
    }
    
    uint32_t used_bytes = n->used_bits;
    while(used_bytes % 0x08 != 0x00){ ++used_bytes; }
    used_bytes /= 0x08;
      
    for(uint32_t x = 0x00; x < amount; ++x){
        for(uint32_t i = 0; i < used_bytes; ++i){
            *(n->bits + i) = *(n->bits + i) >> 0x01;
            if(i != (used_bytes - 0x01) ){ 
                if( (*(n->bits + i + 1)) & 0x01){             
                    (*(n->bits + i)) |= (0x01 << 0x07);   
                }          
            }
        } 
    }  
}

/*   Compare two BigInts. Returns:
 *  
 *   1  if n1 > n2
 *   2  if n1 = n2
 *   3  if n1 < n2
 */
uint8_t bigint_compare2 (struct bigint* n1, struct bigint* n2){
    if(n1->used_bits > n2->used_bits){
        return 1; 
    }
    else if(n1->used_bits < n2->used_bits){
        return 3;
    }
    else{
        uint32_t used_bytes = n1->used_bits;
        while(used_bytes % 0x08 != 0x00){ ++used_bytes; }
        used_bytes /= 0x08;  
        
        for(int32_t i = (used_bytes - 0x01); i >= 0; --i){
            for(int32_t j = 0; j < 8; ++j){
            
                if(  
                       ((*(n1->bits + i) << j) & (0x01 << 0x07))
                   && !((*(n2->bits + i) << j) & (0x01 << 0x07)) 
                  )
                {             
                    return 1;            
                }
                 
                else if(  
                          !((*(n1->bits + i) << j) & (0x01 << 0x07))
                       && ((*(n2->bits + i) << j) & (0x01 << 0x07)) 
                       )
                {             
                    return 3;            
                }
                
                else{ continue; }               
            }
        }
        return 2;  
    }
}

/* Make BigInt n1 equal to the BigInt n2. */
void bigint_equate2(struct bigint* n1, struct bigint* n2){

    if(n1->size_bits < n2->used_bits){ 
        printf("[ERR] Bigint: Equation target has insufficient reserved bits.\n");
        return;
    }
    if(!n2->used_bits){
        bigint_nullify(n1);
        return;
    }
    
    bigint_nullify(n1);
    
    uint32_t aux = n2->used_bits, aux2 = n1->used_bits;
    
    /* Get used bits to next the nearest used byte. */
    while(aux  % 8) { ++aux; }
    while(aux2 % 8) { ++aux2; }
    
    aux  /= 8;   
    aux2 /= 8;
    
    /* If N1 will be made a smaller number than what it currently is,
     * clear the occupied bytes that would not be overwritten by 
     * the new smaller number's bytes.
     */
    if(aux > aux2){
        for(uint32_t i = aux2; i < aux; ++i){
            *(n1->bits + i) = 0x00;
        } 
    }
    
    n1->used_bits = n2->used_bits;
    n1->free_bits = n2->free_bits;
    
    for(uint32_t i = 0x00; i < aux; ++i){
        *(n1->bits + i) = *(n2->bits + i);
    }
     
}



/*  Standard addition of two BigInts.
 *  WARNING: N1, N2 and R's reserved bits must be divisible by 32. 
 *           This will not be checked by the library for performance reasons.
 *
 *           R must have at least 32 more reserved bits than the bigger ADD operand's.
 */
void bigint_add_fast(struct bigint* n1, struct bigint* n2, struct bigint* R){

    bigint_nullify(R);
    
    uint64_t A, B, C, i = 0, carry = 0, temp_res = 0;
    uint8_t* more_bits = NULL;

    if( n1->used_bits < n2->used_bits ){ 
    	A = n2->used_bits; more_bits = n2->bits;
   	}
    else{ 
    	A = n1->used_bits;
    	more_bits = n1->bits;
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
    if(B) { A += (32 - B); }
    A /= 32;

    while(i < (A-1)){
    
        temp_res = 
            (uint64_t)*( ((uint32_t*)(n1->bits)) + i)
            +
            (uint64_t)*( ((uint32_t*)(n2->bits)) + i)
            +
            carry;
            ;

        carry = 0;
            
        if ( temp_res & (1ULL << 32LL) ){
            carry = 1;
        }
           
        *( ((uint32_t*)(R->bits)) + i) = (uint32_t)temp_res;
        
        ++i;
    }
    
    /* ------------------------------------------------------------------------------- */

    temp_res = 
            (uint64_t)*( ((uint32_t*)(n1->bits)) + i)
            +
            (uint64_t)*( ((uint32_t*)(n2->bits)) + i)
            +
            carry;
            ;
                
    *( ((uint32_t*)(R->bits)) + i) = (uint32_t)temp_res;

    uint32_t last_bits_bigger = 31;

    while(! ((*( ((uint32_t*)(more_bits)) + (uint32_t)i)) & ((uint32_t)1 << last_bits_bigger)) ){
        --last_bits_bigger;
    }
 
    if ( temp_res & ((uint64_t)1 << (last_bits_bigger + 1)) ){
            carry = 1;

            /* Carry wasn't accounted for by built-in addition because it was in 33rd bit */
            if(last_bits_bigger == 31){
                *(R->bits + ((i+1) * 4) ) |= (uint8_t)1;
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
void bigint_mul_fast(struct bigint* n1, struct bigint* n2, struct bigint* R){
    bigint_nullify(R);
   
    if(R->size_bits < (n1->used_bits + n2->used_bits) ){
        printf("[ERR] Bigint: MUL Result - not enough reserved bits to store result.\n");
        return;       
    }
    
    if(!n1->used_bits || !n2->used_bits){ return; }
    
    if(n1->used_bits == 1){
        bigint_equate2(R, n2);
        return;
    } 
    
    if(n2->used_bits == 1){
        bigint_equate2(R, n1);
        return;
    }
    
    uint64_t A, B, AA, BB, C, temp_res = 0, i, j, bit_to_check;

    A = n2->used_bits; 
    AA = n1->used_bits;
    B = A % 32;   
    BB = AA % 32;
    if(B) { A += (32 - B); }  
    if(BB){ AA+= (32 - BB); }
    A /= 32;
    AA /= 32;
       
    for(i = 0; i < A; ++i){
        C = 0;
        for(j = 0; j < AA; ++j){
            temp_res = 
                     (uint64_t)(((uint32_t*)R->bits)[i+j]) 
                     +
                     C
                     +
                     (
                        ((uint64_t)(((uint32_t*)n1->bits)[j]) ) 
                        * 
                        ((uint64_t)(((uint32_t*)n2->bits)[i]) )
                     )
                     ;  
     
            ((uint32_t*)R->bits)[i+j] = *( ((uint32_t*)(&temp_res)));
            
            C = (uint64_t)*( ((uint32_t*)(&temp_res)) + 1);
        } 
        ((uint32_t*)R->bits)[i + 1 + (AA - 1)] = *( ((uint32_t*)(&temp_res)) + 1);
    }

    R->used_bits = n1->used_bits + n2->used_bits;
    
    bit_to_check = n1->used_bits + n2->used_bits + 63 - ( (A+AA) * 32 ) ;
    
    if (!(temp_res & ((uint64_t)1 << bit_to_check) )){
        --R->used_bits;    
    }
    
    R->free_bits = R->size_bits - R->used_bits;
    
    return;    
}

/* BigInt n1 to the power of BigInt n2. */
void bigint_pow(struct bigint* n1, struct bigint* n2, struct bigint* R){

    struct bigint n1_used_bits, R_req_bits, zero, one
                 ,R_res_bits, R_temp, starter, starter_temp;

    bigint_create(&R_temp, n2->size_bits, 0);
    bigint_create(&starter, n2->size_bits, 1);
    bigint_create(&starter_temp, n2->size_bits, 1);
    bigint_create(&zero, n2->size_bits, 0);    
    bigint_create(&one, n2->size_bits, 1);    
    bigint_create(&n1_used_bits, n2->size_bits, n1->used_bits);   
    bigint_create(&R_req_bits, n2->size_bits, 0);
    bigint_create(&R_res_bits, n2->size_bits, R->size_bits);

    bigint_nullify(R);
    
    if(n1->size_bits != n2->size_bits){
        printf("[ERR] Bigint: POW operands don't have the same reserved bits.\n");
        goto ret_label;
    }
       
    if( bigint_compare2(n2, &zero) == 2){
        bigint_equate2(R, &one); 
        goto ret_label;  
    }
    
    if( bigint_compare2(n1, &zero) == 2){ goto ret_label; }
        
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
        printf("[ERR] BigInt: Bitlegnth of POW result exceeds 4,290,000,000 bits.\n");
        goto ret_label;
    }
    
    if( bigint_compare2(&R_res_bits, &R_req_bits) == 3){
        printf("[ERR] BigInt: Not enough bits to store the result of POW.\n");
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
void bigint_sub2 (struct bigint* n1, struct bigint* n2, struct bigint* R){

    struct bigint zero, n1_copy;   

    bigint_create(&zero, n2->size_bits, 0);   
    bigint_create(&n1_copy, n1->size_bits, 0);

    bigint_nullify(R);
    
    if( bigint_compare2(n1, n2) == 3){
        printf("[ERR] Bigint: n1 was smaller than n2 in a SUB operation. Returning 0.\n"); 
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
        printf("[ERR] Bigint: Result in SUB doesn't have enough reserved bits.\n");
        goto label_ret;
    }
    
    bigint_equate2(&n1_copy, n1);
        
    uint32_t bigger_used_bytes;

    bigger_used_bytes = n1->used_bits; 
      
    while(bigger_used_bytes % 0x08 != 0x00){ ++bigger_used_bytes; }
    bigger_used_bytes /= 0x08;
    
    uint32_t bit_counter1 = 0, bit_counter2 = 0, old_i = 0, old_j = 0;
    uint8_t borrowing = 0;
     
    for(uint32_t i = 0; i < bigger_used_bytes; ++i){
        for(uint32_t j = 0; j < 8; ++j){

            if(borrowing){
                if( !( ((*(n1_copy.bits + i)) >> j) & 0x01 ) ){
                    (*(n1_copy.bits + i)) |= 0x01 << j;
                    continue;    
                }
                else{
                    (*(n1_copy.bits + i)) ^= 0x01 << j; 
                    i = old_i;
                    j = old_j;
                    borrowing = 0;
                    continue;                   
                }              
            }

            ++bit_counter1;
            
            if(     
                  ( ((*(n1_copy.bits + i)) >> j) & 0x01 )  
               && ( ((*(n2->bits + i)) >> j) & 0x01 )  
              )
              {
                continue;
              }
              
            else if(    
                         ( ((*(n1_copy.bits + i)) >> j) & 0x01 )  
                     && !( ((*(n2->bits + i)) >> j) & 0x01 )  
                   )
                   {
                        (*(R->bits + i)) |= 0x01 << j;
                        bit_counter2 = bit_counter1;
                        continue;                           
                   }
                   
            else if(
                        !( ((*(n1_copy.bits + i)) >> j) & 0x01 )  
                     &&  ( ((*(n2->bits + i)) >> j) & 0x01 )   
                   )
                   {
                        (*(R->bits + i)) |= 0x01 << j;
                        bit_counter2 = bit_counter1;   
                                             
                        borrowing = 1;
                        old_i = i;
                        old_j = j;
                        continue;                     
                   }
                   
            else{ continue; }
        }
    }    
    
    R->used_bits = bit_counter2;  
    R->free_bits = R->size_bits - R->used_bits;
    
label_ret:
    free(zero.bits);
    free(n1_copy.bits);
    
    return;    
}

/* Standard division of two BigInts with integer quotient and remainder. */
void bigint_div2 ( struct bigint* n1, struct bigint* n2
                  ,struct bigint* R,  struct bigint* rem)
                {
                
    bigint_nullify(R);
    bigint_nullify(rem);
    
    struct bigint zero, one, aux, temp_aux, test_aux;
       
    bigint_create(&zero, n2->size_bits, 0); 
    bigint_create(&one, n2->size_bits, 1);  
    bigint_create(&aux, n1->size_bits, 0);
    bigint_create(&temp_aux, n1->size_bits, 0);   
    bigint_create(&test_aux, n1->size_bits, 0);  
         
    if( bigint_compare2(n1, n2) == 3){
        bigint_equate2(rem, n1);
        goto label_ret;  
    }
    if( bigint_compare2(n1, n2) == 2){ 
        bigint_equate2(R, &one);
        printf("[DIV]: RET 1\n");
        goto label_ret; 
    }    
    if( bigint_compare2(n2, &one) == 2){ 
        bigint_equate2(R, n1);
        printf("[DIV]: RET 2\n");
        goto label_ret;
    }            
    if( bigint_compare2(n2, &zero) == 2){
        printf("[ERR] Bigint: DIV by zero attempted. Returning 0.\n"); 
        goto label_ret; 
    }
    if(R->size_bits < n1->used_bits){
        printf("[ERR] Bigint: Result in DIV doesn't have enough reserved bits.\n");
        goto label_ret;
    }
    if(rem->size_bits < n1->used_bits){
        printf("[ERR] Bigint: Remainder in DIV doesn't have enough reserved bits.\n");
        goto label_ret;
    }    
       
    int32_t bigger_used_bytes;
    
    bigger_used_bytes = n1->used_bits; 
      
    while(bigger_used_bytes % 0x08 != 0x00){ ++bigger_used_bytes; }
    bigger_used_bytes /= 0x08;
    
    uint8_t first_one_found = 0, done = 0; 

    for(int32_t i = bigger_used_bytes - 1; i >= 0; --i){
        for(int8_t j = 7; j >= 0; --j){ 
            bigint_equate2(&temp_aux, &aux);
            bigint_add_fast(&temp_aux, &temp_aux, &aux);

            if( ((*(n1->bits + i)) >> j) & 0x01 ){
                bigint_equate2(&temp_aux, &aux);          
                bigint_add_fast(&temp_aux, &one, &aux); 
            }
  
            if(bigint_compare2(&aux, n2) != 3){
                (*(R->bits + i)) |= 0x01 << j; 
              
                if(!first_one_found){
                    first_one_found = 1;
                    R->used_bits = i*8 + (j + 1);
                    R->free_bits = R->size_bits - R->used_bits;
                }

                bigint_equate2(&temp_aux, &aux);
                bigint_sub2(&temp_aux, n2, &aux);       
            }
            
            if( i == 0 && j == 0 ){             
                bigint_equate2(rem, &aux);            
                done = 1;
                break;
            }      
        }
        if(done){ break; }
    } 
    
    if(bigint_compare2(rem, n2) == 1){
        printf("[ERR] BigInt: Division remainder is bigger than what we divided by.\n");
        printf("DIV RESULT:\n");
        bigint_print_info(R);
        bigint_print_all_bits(R);        
        printf("REMAINDER:\n");
        bigint_print_info(rem);
        bigint_print_all_bits(rem);
        exit(1);
    } 
    
label_ret:
    free(zero.bits); 
    free(one.bits); 
    free(aux.bits); 
    free(temp_aux.bits);
    return; 
} 

/* Modular Multiplication. Multiply many BigInts, modulo another BigInt. */
void bigint_mod_mul(struct bigint** nums, struct bigint* mod, uint32_t how_many, struct bigint* R){
    struct bigint div_res, rem, mul_res;

    bigint_create(&div_res, nums[0]->size_bits, 1);
    bigint_create(&mul_res, nums[0]->size_bits, 1);
    bigint_create(&rem,     nums[0]->size_bits, 1);

    bigint_equate2(R, &rem); 
    
    if(how_many < 2) {
        printf("[ERR] BigInt: Modular MUL - fewer than 2 BigInts were supplied.\n");
        goto label_ret;
    }
    
    uint8_t compare_res = 0;

    /* The long loop */
    for(uint32_t i = 0; i < how_many; ++i){
        printf("[BigInt] - Long loop in MOD_MUL moved  i = %u to %u"
              " (how many big numbers we multiply).\n"
              , i, how_many
              ); 
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
void bigint_mod_pow(struct bigint* N, struct bigint* P, struct bigint* M, struct bigint* R){

    bigint_nullify(R);

    struct bigint aux1, aux2, two, div_res, one, zero;

    bigint_create(&aux1, M->size_bits, 1);
    bigint_create(&aux2, M->size_bits, 1);
    bigint_create(&two,  M->size_bits, 2);
    bigint_create(&one,  M->size_bits, 1);
    bigint_create(&zero, M->size_bits, 0);
    bigint_create(&div_res, M->size_bits, 1);
    
    uint32_t *arr1 = NULL
            ,c1 = 0
            ,P_used_bytes = P->used_bits
            ,arr1_curr_ind = 0;
            ;
             
    struct bigint  *arr2 = NULL
                 ,**arr_ptrs = NULL;
    
    if(R->size_bits < M->used_bits){
        printf("[ERR] BigInt: Modulo Power, not enough reserved bits in input Result.\n");
        goto label_ret;
    }
    
    if( !(M->size_bits > (2 * M->used_bits)) ){
        printf("[ERR] BigInt: mod_pow: M's reserved bits need to be > (2 * M's used bits)\n");
        goto label_ret;
    }
    
    if(bigint_compare2(M, &zero) == 2){
        printf("[ERR] BigInt: mod_pow: Attempted to take remainder after dividing by zero.\n");
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
    if(bigint_compare2(N, &zero) == 2){ goto label_ret; }
    
    if(bigint_compare2(N, &one) == 2){
        bigint_equate2(R, &one);
        goto label_ret;
    }

    arr1 = (uint32_t*)malloc(P->used_bits * (sizeof(uint32_t)));

    while(P_used_bytes % 8) { 
        ++P_used_bytes; 
    }
    
    P_used_bytes /= 8;

    for(uint32_t i = 0; i < P_used_bytes; ++i){
        for(uint8_t j = 0; j < 8; ++j){
            if( ( (*(P->bits + i)) >> j) & 0x01){
                arr1[arr1_curr_ind] = (i * 8) + j;
                ++arr1_curr_ind;
                ++c1;
            }      
        }
    }
    
    arr2 = (struct bigint*)malloc(c1 * sizeof(struct bigint));
    arr_ptrs = (struct bigint**)malloc(c1 * sizeof(struct bigint*));
   
    for(uint32_t i = 0; i < c1; ++i){
        bigint_create(&(arr2[i]), M->size_bits, 1); 
        arr_ptrs[i] = &arr2[i];
    }

    arr1_curr_ind = 0;  
     
    bigint_div2(N, M, &div_res, &aux1);

    /* The long loop */
    for(uint32_t i = 0; i < P->used_bits; ++i){   
    
     
        printf("[BigInt] - Long loop in MOD_POW moved  i = %u to %u"
               " (power's used bits).\n"
               , i, P->used_bits
               ); 
               
               
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
    if(arr2){
        for(uint32_t i = 0; i < c1; ++i){
            free(arr2[i].bits);
        }   
        free(arr_ptrs);  
        free(arr2);
    }   
    if(arr1){ 
        free(arr1); 
    }
    free(aux1.bits);
    free(aux2.bits);
    free(div_res.bits);
    free(two.bits);
}


/* Fast algorithm for determining whether a BigInt is prime or not. */
/* Returns 1 if the big number is prime, or 0 otherwise. */
uint8_t Rabin_Miller(struct bigint* N, uint32_t passes){
    
    struct bigint N_minus_one, zero, one, two, M, B0, Bi_prev, Bi, div_res, rem, aux1;
    
    bigint_create(&N_minus_one, N->size_bits, 0);
    bigint_create(&one, N->size_bits, 1);
    bigint_create(&two, N->size_bits, 2);   
    bigint_create(&N_minus_one, N->size_bits, 0);
    
    bigint_sub2(N, &one, &N_minus_one);

    bigint_create(&M,       N->size_bits, 0);
    bigint_create(&B0,      N->size_bits, 0);
    bigint_create(&Bi_prev, N->size_bits, 0);
    bigint_create(&Bi,      N->size_bits, 0);
    bigint_create(&div_res, N->size_bits, 0);
    bigint_create(&rem,     N->size_bits, 0);
    bigint_create(&zero,    N->size_bits, 0);
    bigint_create(&aux1,    N->size_bits, 0);
    
    uint32_t K = 0, A_val = 2, curr_A_ind = 0, prime_votes = 0;
    uint8_t K_flag = 1, ret = 0, lab_b0_flag = 0, lab_ret_flag = 0;
        
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
    struct bigint* As = (struct bigint*)malloc(( (passes * 2) + 1) * sizeof(struct bigint));
    for(uint32_t i = 0; i < (passes * 2) + 1; ++i){
        bigint_create(&(As[i]), N->size_bits, A_val);
        ++A_val;
    }

label_B0:
    lab_b0_flag = 0;

    /* Compute this A's b0 */
    bigint_mod_pow(&(As[curr_A_ind]), &M, N, &B0);

    if( (bigint_compare2(&B0, &one) == 2) || (bigint_compare2(&B0, &N_minus_one) == 2) ){
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
        for(uint32_t i = 1; i < K; ++i){
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
        if(lab_ret_flag) { goto label_ret; }
        if(lab_b0_flag)  { goto label_B0;  }
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
    for(uint32_t i = 0; i < (passes * 2) + 1; ++i){
        free(As[i].bits);
    }
    free(As);
    return ret;
 }




				  



