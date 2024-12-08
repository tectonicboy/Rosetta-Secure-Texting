#include "cryptolib.h"

/* Generate a new pseudorandom private key. */
void gen_priv_key(uint32_t len_bytes, uint8_t* buf){
    
    FILE* ran = fopen("/dev/urandom","r");
    
    if(ran == NULL){
        printf("[ERROR] Priv key gen - couldn't open /dev/urandom.\n");
        exit(1);
    }
    
    size_t bytes_read;
    
    if (  (bytes_read = fread((void*)buf, 1, len_bytes, ran)) != len_bytes){
        printf("[ERROR] Priv key gen - couldn't read %u bytes from urandom.\n"
               ,len_bytes
              );
        fclose(ran);
        exit(1);
    }
    
    printf("[OK] Successfully generated %u-byte private key!\n", len_bytes);
    fclose(ran);
    return;
}

/* Given a private key, generate its corresponding public key. */
struct bigint* gen_pub_key( uint32_t privkey_len_bytes
                           ,const char* privkey_filename
                           ,uint32_t resbits
){
    
    FILE* privkey_dat = fopen(privkey_filename, "r");
    
    if(privkey_dat == NULL){
        printf("[ERROR] gen_pub_key - couldnt open privkey file. Ret NULL.\n");
        return NULL;
    }

    uint8_t* privkey_buf = (u8*)malloc(privkey_len_bytes);
    size_t bytes_read;
    
    if ( 
            (bytes_read = fread(privkey_buf, 1, privkey_len_bytes, privkey_dat)) 
         != 
            privkey_len_bytes
       ){
        printf("[ERR] pub_key_gen - couldn't read %u bytes from privkey_file.\n"
               ,privkey_len_bytes
              );
        fclose(privkey_dat);
        return NULL;
    }
    
    printf("[OK] Successfully read %u bytes from privkey_file\n"
           ,privkey_len_bytes
    );
    fclose(privkey_dat);
    
    struct bigint* privkey_bigint = (bigint*)malloc(sizeof(struct bigint));
    
    privkey_bigint->bits = privkey_buf;
    privkey_bigint->size_bits = resbits;
    privkey_bigint->used_bits = get_used_bits(privkey_buf, privkey_len_bytes);
    privkey_bigint->free_bits = 
            privkey_bigint->size_bits - privkey_bigint->used_bits;
            
            
    struct bigint *M
                 ,*Gm
                 ,*R = (bigint*)malloc(sizeof(struct bigint))
                 ;
    

    
    M = get_BIGINT_from_DAT( 3072
                            ,"../saved_nums/saved_M.dat\0"
                            ,3071
                            ,12800
                              );
    
    Gm = get_BIGINT_from_DAT( 3072
                            ,"../saved_nums/saved_Gm.dat\0"
                            ,3071
                            ,12800
                           );

    bigint_create(R, M->size_bits, 0);
    
    MONT_POW_modM(Gm, privkey_bigint, M, R); 

    printf("Computed public key:\n");
    
    bigint_print_info(R);
    bigint_print_bits(R);

    free(privkey_buf);
    free(privkey_bigint);
    
    return R;    
}

/* Check that a public key is of the correct form given our DH parameters. 
 *
 * The check is: 
 *
 *      pub_key^(M/Q) mod M == 1 
 *
 *  Return 1 for valid and 0 for invalid public key.
 */
 
bool check_pubkey_form( bigint* Km
                       ,bigint* M
                       ,bigint* Q)
{
    bigint M_over_Q
          ,one
          ,div_rem
          ,mod_pow_res;
          
    bool ret = 1;
    
    bigint_create(&M_over_Q,    12800, 0);
    bigint_create(&one,         12800, 1);
    bigint_create(&div_rem,     12800, 0);
    bigint_create(&mod_pow_res, 12800, 0); 
       
    bigint_div2(M, Q, &M_over_Q, &div_rem);
    
    MONT_POW_modM( Km
                  ,&M_over_Q
                  ,M
                  ,&mod_pow_res
                 );
    
    if(bigint_compare2(&mod_pow_res, &one) != 2){
        printf("[ERR] Public key didn't pass (pub_key^(M/Q) mod M == 1)\n\n");
        ret = 0;
    }
    
    free(M_over_Q.bits);
    free(one.bits);
    free(div_rem.bits);
    free(mod_pow_res.bits);
    
    return ret;
}




