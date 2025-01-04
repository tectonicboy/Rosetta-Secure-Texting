#include "cryptolib.h"

/* Generate a new pseudorandom private key. */
void gen_priv_key(uint32_t len_bytes, uint8_t* buf){
    
    size_t bytes_read;

    FILE* ran = fopen("/dev/urandom", "r");

    if(ran == NULL){
        printf("[ERR] utilities: gen_priv_key - couldn't open urandom.\n\n");
        return;
    }
    
    if ( (bytes_read = fread((void*)buf, 1, len_bytes, ran)) != len_bytes ){

        printf("[ERR] utilities: gen_priv_key - couldn't read %u bytes "
               "from urandom.\n\n"
               ,len_bytes
        );

        fclose(ran);

        return;
    }
    
    printf("[OK] utilities: Generated a %u-byte private key!\n\n", len_bytes);

    fclose(ran);

    return;
}

/* Given a private key, generate its corresponding public key. */
struct bigint* gen_pub_key( uint32_t privkey_len_bytes
                           ,const char* privkey_filename
                           ,uint32_t resbits
                          )
{
    struct bigint* M;
    struct bigint* Gm;
    struct bigint* R = (bigint*)calloc(1, sizeof(struct bigint));
    struct bigint  privkey_bigint;

    u8* privkey_buf = (u8*)calloc(1, privkey_len_bytes);

    size_t bytes_read;

    FILE* privkey_dat;
    
    privkey_dat = fopen(privkey_filename, "r");
    
    M  = get_BIGINT_from_DAT(3072, "../bin/saved_M.dat\0",  3071, 12800);
    Gm = get_BIGINT_from_DAT(3072, "../bin/saved_Gm.dat\0", 3071, 12800);

    if(privkey_dat == NULL){
        printf("[ERR] utilities: gen_pub_key - couldn't open privkey file\n\n");
        goto label_cleanup;
    }

    if ( (bytes_read = fread(privkey_buf, 1, privkey_len_bytes, privkey_dat)) 
         != privkey_len_bytes
       )
    {
        printf( "[ERR] utilities: gen_pub_key - couldn't read %u bytes from "
                "privkey_file.\n\n"
               ,privkey_len_bytes
              );

        goto label_cleanup;
    }
    
    printf("[DEBUG] coreutil: Read %lu bytes from privkeyfile:\n", bytes_read);
    for(u64 i = 0; i < bytes_read; ++i){
        printf("%u ", privkey_buf[i]);
        if(i % 16 == 0 && i > 15){
            printf("\n");
        }
    }
    printf("\n\n");

    privkey_bigint.bits = privkey_buf;
    privkey_bigint.size_bits = resbits;
    privkey_bigint.used_bits = get_used_bits(privkey_buf, privkey_len_bytes);
    privkey_bigint.free_bits = 
            privkey_bigint.size_bits - privkey_bigint.used_bits;
                
    bigint_create(R, M->size_bits, 0);
    
    MONT_POW_modM(Gm, &privkey_bigint, M, R); 

label_cleanup:

    if(privkey_dat != NULL){
        fclose(privkey_dat);
    }

    free(privkey_buf);
    free(M);
    free(Gm);

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
 
bool check_pubkey_form(bigint* Km, bigint* M, bigint* Q)
{
    bigint M_over_Q;
    bigint one;
    bigint div_rem;
    bigint mod_pow_res;
          
    bool ret = 1;
    
    bigint_create(&M_over_Q,    12800, 0);
    bigint_create(&one,         12800, 1);
    bigint_create(&div_rem,     12800, 0);
    bigint_create(&mod_pow_res, 12800, 0); 
       
    bigint_div2(M, Q, &M_over_Q, &div_rem);
    
    MONT_POW_modM(Km, &M_over_Q, M, &mod_pow_res);
    
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




