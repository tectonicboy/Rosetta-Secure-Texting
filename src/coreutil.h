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
struct bigint* gen_pub_key(uint32_t privkey_len_bytes, char* privkey_filename
						  ,uint32_t resbits
){
	
	FILE* privkey_dat = fopen(privkey_filename, "r");
	
	if(privkey_dat == NULL){
		printf("[ERROR] gen_pub_key - couldnt open privkey file. Ret NULL.\n");
		return NULL;
	}

	uint8_t* privkey_buf = malloc(privkey_len_bytes);
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
	
	struct bigint* privkey_bigint = malloc(sizeof(struct bigint));
	
	privkey_bigint->bits = privkey_buf;
	privkey_bigint->size_bits = resbits;
	privkey_bigint->used_bits = get_used_bits(privkey_buf, privkey_len_bytes);
	privkey_bigint->free_bits = 
			privkey_bigint->size_bits - privkey_bigint->used_bits;
			
			
	struct bigint *M
			     ,*Gm
			     ,*R = malloc(sizeof(struct bigint))
			     ;
	

	
	M = get_BIGINT_from_DAT( 3072
    				    	,"../saved_nums/M_raw_bytes.dat\0"
    				    	,3071
    				    	,12800
    				   	   );
    
    Gm = get_BIGINT_from_DAT( 3072
						    ,"../saved_nums/PRACTICAL_Gmont_raw_bytes.dat\0"
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
