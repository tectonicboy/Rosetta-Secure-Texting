void create_save(const char* pass_txt, uint16_t pass_len){
	
 	/* Step 1 - generate the user's private key. */
 	FILE* client_privkey_dat = fopen("client_privkey.dat","w");
	if(client_privkey_dat == NULL){
		printf("[ERR] - client_util.h - couldn't open client_privkey.dat\n");
		goto label_cleanup;
	}
	
	
	uint32_t req_key_len_bytes = 40;
	uint8_t* privkey_buf = malloc(req_key_len_bytes);
	size_t bytes_wr;
	
	gen_priv_key(req_key_len_bytes, privkey_buf);
	
	/* Turn off bit index 1 to make it guaranteed less than Q. */	   
	privkey_buf[req_key_len_bytes - 1] &= ~(1 << 7);

	bytes_wr = fwrite(privkey_buf, 1, req_key_len_bytes, client_privkey_dat);
	
	if(bytes_wr != req_key_len_bytes){
		printf("[ERR] - client_util.h couldnt write %u bytes to "
			   "client_privkey.dat\n", req_key_len_bytes);
		goto label_cleanup;
	}

	printf("[OK] Successfully wrote %u bytes to client_privkey.dat\n"
		   ,req_key_len_bytes
	);
	
	/* Close privkey file here, not at final cleanup, because gen_pub_key()
	 * also requires to open that file and read from it, irrespective of 
	 * what its callers did with that file.
	 */
	fclose(client_privkey_dat);
	
	
	/* DONE generating user's private key. */
	
	/* Step 2 - compute the user's public key and its Montgomery form. */
	uint32_t privkey_len_bytes = 40;

	struct bigint *pubkey_bigint
		         ,*pubkey_montform = malloc(sizeof(struct bigint))
		         ,*M
		         ;
		         
     M = get_BIGINT_from_DAT( 3072
		    	,"../saved_nums/M_raw_bytes.dat\0"
		    	,3071
		    	,12800
		   	   );
		         
	bigint_create(pubkey_montform, 12800, 0);
	
	pubkey_bigint = 
	         gen_pub_key(privkey_len_bytes, "client_privkey.dat\0", 12800);
	
	uint32_t pubkey_used_bytes = pubkey_bigint->used_bits;
	
	while(pubkey_used_bytes % 8){
		++pubkey_used_bytes;
	}
	pubkey_used_bytes /= 8;
	
	FILE* client_pubkey_dat = fopen("client_pubkey.dat","w");
	if(client_pubkey_dat == NULL){
		printf("[ERR] Failed to open client_pubkey.dat during REG.\n");
		goto label_cleanup;
	}
	bytes_wr = 
	     fwrite(pubkey_bigint->bits, 1, pubkey_used_bytes, client_pubkey_dat);
	
	if(bytes_wr != pubkey_used_bytes){
		printf("[ERR] - client_uilt.h couldn't write %u bytes to "
			   "client_pubkey.dat\n", pubkey_used_bytes);
		goto label_cleanup;
	}

	printf("[OK] Successfully wrote %u bytes to client_pubkey.dat\n"
		   ,pubkey_used_bytes
		  );
		  
	printf("\nNow generating Montgomery form of the client's public key.\n");
	
	Get_Mont_Form(pubkey_bigint, pubkey_montform, M);
	
	
	uint32_t pubkeymont_used_bytes = pubkey_montform->used_bits;
	
	while(pubkeymont_used_bytes % 8){
		++pubkeymont_used_bytes;
	}
	pubkeymont_used_bytes /= 8;
	
	FILE* client_pubkeymont_dat = fopen("client_pubkeymont.dat","w");
	if(client_pubkeymont_dat == NULL){
		printf("[ERR] Failed to open client_pubkeymont.dat during REG.\n");
		goto label_cleanup;
	}
	bytes_wr = 
	     fwrite(pubkey_montform->bits, 1, pubkeymont_used_bytes
	     	    ,client_pubkeymont_dat
	     	   );
	
	if(bytes_wr != pubkeymont_used_bytes){
		printf("[ERR] - gen_pub_key couldnt write %u bytes to "
			   "client_pubkeymont.dat\n", pubkeymont_used_bytes);
		goto label_cleanup;
	}

	printf("[OK] Successfully wrote %u bytes to client_pubkeymont.dat\n"
		   ,pubkeymont_used_bytes
		  );
	
	printf("Montgomery form of public key generated:\n");
	bigint_print_info(pubkey_montform);
	bigint_print_bits(pubkey_montform);
	
	int del_rc;
	if( (del_rc = remove("client_privkey.dat")) != 0){
		printf("[ERR] - client_util couldn't delete PRIVKEY plain file.\n");
		goto label_cleanup;
	}

	/* DONE generating user's public key and its Montgomery form. */
	
	/* Step 3.Use Argon2 to get a hash of the entered password. */
	struct Argon2_parms prms;
	memset(&prms, 0x00, sizeof(struct Argon2_parms));
	    
    prms.p = 8;   
    prms.T = 64;  
    prms.m = 2097000;  
    prms.t = 1;  
    prms.v = 19;  
    prms.y = 2;  
    
    char *P = malloc(pass_len) 	/* initialize from passed pass_txt, pass_len */
    							/* Generate a random 8-byte string S.        */
        ,*S = malloc(8+64)     	/* Salt= S||BLAKE2B{64}(user's public key);  */
         ;				      
        
    FILE* ran = fopen("/dev/urandom","r");
    if(ran == NULL){
    	printf("[ERR] Failed to open /dev/urandom during registration.\n");
    	goto label_cleanup;
    } 
    
    if (  (fread((void*)S, 1, 8, ran)) != 8){
		printf("[ERR] Couldn't read 8 bytes from urandom during REG.\n");
		goto label_cleanup;
	}
      
    /* Salt= S||BLAKE2B{64}(user's public key);  */   

    BLAKE2B_INIT(pubkey_bigint->bits, pubkey_used_bytes, 0, 64, (S + 8) );
         					 

    /* Copy the passed password buffer into Argon2 password parameter. */
    memcpy(P, pass_txt, pass_len);
    

    prms.P = P;
    prms.S = S;

    
    prms.len_P = pass_len;
    prms.len_S = 8+64; /* 8 byte string + blake2b{64}(public_key) */
    prms.len_K = 0 ;   /* unused here. */
    prms.len_X = 0;    /* unused here. */
    
    char* argon2_output_tag = malloc(prms.T);
	char* V = malloc(40); /* bitwidth of our current Q is 40 bytes*/
    Argon2_MAIN(&prms, argon2_output_tag);
 

    printf("\n\n***** ARGON2id produced %lu-byte Tag: ******\n\n", prms.T);
    
    for(uint32_t i = 0; i < prms.T; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)argon2_output_tag[i]);
    }
    printf("\n\n");
    
    
    /* Step 4 - Use Argon2's output hash as the key in ChaCha20 to       */
    /*			encrypt the private key and save only the encrypted one. */
    
    
    char* plaintext = (char*)privkey_buf;
                      
    uint32_t msg_len = req_key_len_bytes; /* 40 bytes right now */
                      
    uint32_t* key = (uint32_t*)(argon2_output_tag + (uint64_t)(prms.T / 2));
    
    /* NOTE: nonce_len and key_len are measured in number of uint32_t's!! */
    
    uint8_t key_len = 8; /* ChaCha20 key is always 32 (8*4) bytes */

    uint8_t nonce_len = 4;
    uint32_t* nonce = malloc(nonce_len*4 * sizeof(uint32_t));
	
	if (  (fread((void*)nonce, 1, nonce_len*4, ran)) != nonce_len*4){
		printf(
				"[ERROR] Couldn't read %u bytes from urandom during REG.\n"
			   ,nonce_len*4
		);
		goto label_cleanup;
	}

    char* cyphertext = malloc(msg_len * sizeof(char));
    memset(cyphertext, 0x00, msg_len * sizeof(char));
    
    CHACHA20(plaintext, msg_len, nonce, nonce_len, key, key_len, cyphertext);
    
    printf("THE CYPHERTEXT FROM CHACHA20 - encrypted private key:\n");
    
    for(uint32_t i = 0; i < msg_len; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)cyphertext[i]);

    }
    printf("\n");
    
    /* Save the encrypted private key to file. */
    
	FILE* encrypted_privkey = fopen("encrypted_privkey.dat","w");
	
	if(!encrypted_privkey){
		printf("[ERR] Couldn't open encrypted_privkey.dat during REG.\n");
		goto label_cleanup;
	}
	
	bytes_wr = fwrite(cyphertext, 1, msg_len, encrypted_privkey);
	
	if(bytes_wr != msg_len){
		printf("[ERR] - client_util.h couldnt write %u bytes to "
			   "encrypted_privkey.dat\n", msg_len);
		goto label_cleanup;
	}

	printf("[OK] Successfully wrote %u bytes to encrypted_privkey.dat\n"
		   ,msg_len
	);

label_cleanup:

	/* Different things will need to be cleaned up depending on whether we
	 * arrived here due to an error or by natural code flow. Hence the checking.
	 */

	if(ran)			           	{fclose(ran);}
    if(client_pubkey_dat)      	{fclose(client_pubkey_dat);}
    if(client_pubkeymont_dat)	{fclose(client_pubkeymont_dat);}
    if(encrypted_privkey)		{fclose(encrypted_privkey);}	  	
	if(privkey_buf)			   	{free(privkey_buf);}
	if(pubkey_montform)		   	{free(pubkey_montform);}
	if(P)				       	{free(P);}
	if(S)					   	{free(S);}
	if(V)					   	{free(V);}
	if(argon2_output_tag)      	{free(argon2_output_tag);}
	if(nonce)				   	{free(nonce);}
	if(cyphertext)			   	{free(cyphertext);}
	
    return;
}

void login(const char* pass_txt, uint16_t pass_len){
	/* Can reuse a large part of create_save(). */
}
