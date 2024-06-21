uint8_t create_save(const char* pass_txt, uint16_t pass_len){
	printf("REG passed pass: %s\n", pass_txt);
	uint8_t status = 0;
	
 	/* Step 1 - generate the user's private key. */
 	FILE* client_privkey_dat = fopen("client_privkey.dat","w");
	if(client_privkey_dat == NULL){
		printf("[ERR] - client_util.h - couldn't open client_privkey.dat\n");
		status = 1;
		goto label_cleanup_reg;
	}
	
	
	uint32_t req_key_len_bytes = 40;
	uint8_t* privkey_buf = malloc(req_key_len_bytes);
	size_t bytes_wr;
	
	gen_priv_key(req_key_len_bytes, privkey_buf);
	
	/* Turn off bit index 1 to make it guaranteed less than Q. */	   
	privkey_buf[req_key_len_bytes - 1] &= ~(1 << 7);
	
	printf("REG ---->> THE PRIVATE KEY plainly:\n");
    
    for(uint32_t i = 0; i < req_key_len_bytes; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)privkey_buf[i]);
    }
    printf("\n");	
    
	bytes_wr = fwrite(privkey_buf, 1, req_key_len_bytes, client_privkey_dat);
	
	if(bytes_wr != req_key_len_bytes){
		printf("[ERR] - client_util.h couldnt write %u bytes to "
			   "client_privkey.dat\n", req_key_len_bytes);
		status = 1;
		goto label_cleanup_reg;
	}
	printf("[OK] Successfully wrote %u bytes to client_privkey.dat\n"
		   ,req_key_len_bytes
	);
	
	/* Close privkey file here, not at final cleanup_reg, because gen_pub_key()
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
		status = 1;
		goto label_cleanup_reg;
	}
	bytes_wr = 
	     fwrite(pubkey_bigint->bits, 1, pubkey_used_bytes, client_pubkey_dat);
	
	if(bytes_wr != pubkey_used_bytes){
		printf("[ERR] - client_uilt.h couldn't write %u bytes to "
			   "client_pubkey.dat\n", pubkey_used_bytes);
		status = 1;
		goto label_cleanup_reg;
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
		status = 1;
		goto label_cleanup_reg;
	}
	bytes_wr = 
	     fwrite(pubkey_montform->bits, 1, pubkeymont_used_bytes
	     	    ,client_pubkeymont_dat
	     	   );
	
	if(bytes_wr != pubkeymont_used_bytes){
		printf("[ERR] - gen_pub_key couldnt write %u bytes to "
			   "client_pubkeymont.dat\n", pubkeymont_used_bytes);
		status = 1;
		goto label_cleanup_reg;
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
		status = 1;
		goto label_cleanup_reg;
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
    
    uint8_t *P = malloc(pass_len) 	/* initialize from passed pass_txt, pass_len */
    							/* Generate a random 8-byte string S.        */
        ,*S = malloc(8+64)     	/* Salt= S||BLAKE2B{64}(user's public key);  */
         ;				      
        
    FILE* ran = fopen("/dev/urandom","r");
    if(ran == NULL){
    	printf("[ERR] Failed to open /dev/urandom during registration.\n");
    	status = 1;
    	goto label_cleanup_reg;
    } 
    
    if (  (fread((void*)S, 1, 8, ran)) != 8){
		printf("[ERR] Couldn't read 8 bytes from urandom during REG.\n");
		status = 1;
		goto label_cleanup_reg;
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
    
    uint8_t* argon2_output_tag = malloc(prms.T);
	memset(argon2_output_tag, 0x00, prms.T);
	
    Argon2_MAIN(&prms, argon2_output_tag);
 

    printf("\n\n***** REG ARGON2id produced %lu-byte Tag: *****\n\n", prms.T);
    
    for(uint32_t i = 0; i < prms.T; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)argon2_output_tag[i]);
    }
    printf("\n\n");
    
    
    /* Step 4 - Use Argon2's output hash as the key in ChaCha20 to       */
    /*			encrypt the private key and save only the encrypted one. */
    
    
    uint8_t* plaintext = (uint8_t*)privkey_buf;
                      
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
		status = 1;
		goto label_cleanup_reg;
	}

    uint8_t* cyphertext = malloc(msg_len * sizeof(uint8_t));
    memset(cyphertext, 0x00, msg_len * sizeof(uint8_t));
    
    CHACHA20(plaintext, msg_len, nonce, nonce_len, key, key_len, cyphertext);
    
    printf("THE REG CYPHERTEXT FROM CHACHA20 - encrypted private key:\n");
    
    for(uint32_t i = 0; i < msg_len; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)cyphertext[i]);

    }
    printf("\n");
    

    /* Nonce + encrypted private key + public key + string S */
    /* Total size: 16 + 40 + 384 + 8 = 448 bytes */

    /* Save them to file. */
    
	FILE* savefile = fopen("saved.dat","w");
	
	if(!savefile){
		printf("[ERR] clutil couldn't open saved.dat during REG.\n");
		status = 1;
		goto label_cleanup_reg;
	}
	
	if( (bytes_wr = fwrite(nonce, 1, nonce_len*4, savefile)) != nonce_len*4){
		printf("[ERR] clutil didnt write %u bytes to saved.dat\n", nonce_len*4);
		status = 1;
		goto label_cleanup_reg;
	}
	
	if( (bytes_wr = fwrite(cyphertext, 1, msg_len, savefile)) != msg_len){
		printf("[ERR] clutil couldnt write %u bytes to saved.dat\n", msg_len);
		status = 1;
		goto label_cleanup_reg;
	}
	if( (bytes_wr = fwrite(pubkey_bigint->bits, 1, 384, savefile)) != 384){
		printf("[ERR] clutil couldnt write 384 bytes to saved.dat\n");
		status = 1;
		goto label_cleanup_reg;
	}
	if( (bytes_wr = fwrite(S, 1, 8, savefile)) != 8){
		printf("[ERR] clutil couldnt write 8 bytes to saved.dat\n");
		status = 1;
		goto label_cleanup_reg;
	}

	printf("[OK] Successfully wrote %u bytes to saved.dat\n"
		   ,( (nonce_len*4) + msg_len + 384 + 8)
	);

label_cleanup_reg:

	/* Different things will need to be cleaned up depending on whether we
	 * arrived here due to an error or by natural code flow. Hence the checking.
	 */

	if(ran)			           	{fclose(ran);}
    if(client_pubkey_dat)      	{fclose(client_pubkey_dat);}
    if(client_pubkeymont_dat)	{fclose(client_pubkeymont_dat);}
    if(savefile)				{fclose(savefile);}	  	
	if(privkey_buf)			   	{free(privkey_buf);}
	if(pubkey_montform)		   	{free(pubkey_montform);}
	if(P)				       	{free(P);}
	if(S)					   	{free(S);}
	if(argon2_output_tag)      	{free(argon2_output_tag);}
	if(nonce)				   	{free(nonce);}
	if(cyphertext)			   	{free(cyphertext);}
	
	if(status){
		printf("\n\n\n******* WARNING *******\n\n Registration error!\n\n");
		printf("Look back in the log to locate the exact error [ERR] line.\n");
	}
	else{
		printf("\n\n\n****** Registration SUCCESS!! ******\n\n\n");
	}
    return status;
}

uint8_t login(const char* pass_txt, uint16_t pass_len){
	/* Can reuse a large part of create_save(). */

	/* Will read saved.dat */

	/* Make sure the save file contains the exact number of required bytes,
	 * no less, no more. If not, force a new registration. 
	 */
	 printf("Passed the password of len %u: %s\n", pass_len, pass_txt);
	 uint8_t status = 0;
	 
	uint32_t 
	  req_save_siz_bytes = 448    /* Mandatory size of a correct savefile.    */
	 ,nonce_siz 		 = 16	 
	 ,encr_privkey_siz   = 40     
	 ,pubkey_siz		 = 384
	 ,S_siz				 = 8
	 ;
	 
	 uint8_t
	  *savefile_buf = malloc(512) /* Memory space for savefile contents.	  */
	 ,*nonce 		  			  /* Pointer to saved nonce of ChaCha20 usage.*/	
	 ,*encr_privkey   			  /* Pointer to saved Encrypted private key.  */
	 ,*pubkey					  /* Pointer to saved Public key.			  */
	 ,*S		   			      /* Pointer to Saved String S for Argon2id.  */
	 ;
	

	
	FILE* saved = fopen("saved.dat", "r");
	 							
	if(!saved){
		printf("[ERR] clutil couldnt open saved.dat\n");
		status = 1;
		goto label_cleanup_log;	 		
	}
	
	
	/* Intentionally try to read more than needed, to catch a corrupted save. */
	if (  (fread((void*)savefile_buf, 1, 512, saved)) != req_save_siz_bytes){
		printf(
				"[ERROR] Couldn't read %u bytes from saved.dat during LOG.\n"
			   ,req_save_siz_bytes
		);
		status = 1;
		goto label_cleanup_log;
	}	
	
	/* Set the pointers to the parts of the savefile appropriately. */
	nonce 		 = savefile_buf + 0;
	encr_privkey = savefile_buf + nonce_siz;
	pubkey 		 = savefile_buf + (nonce_siz + encr_privkey_siz);
	S 			 = savefile_buf + (nonce_siz + encr_privkey_siz + pubkey_siz);
	
	/* Step 3.Use Argon2 to get a hash of the entered password. */
	struct Argon2_parms prms;
	memset(&prms, 0x00, sizeof(struct Argon2_parms));
	    
    prms.p = 8;   
    prms.T = 64;  
    prms.m = 2097000;  
    prms.t = 1;  
    prms.v = 19;  
    prms.y = 2;  
    
    uint8_t *P = malloc(pass_len)   /* initialize from passed pass_txt, pass_len */
        ,*Salt = malloc(8+64)    /* Salt= S||BLAKE2B{64}(user's public key);  */
         ;				      
         
    /* Salt= S||BLAKE2B{64}(user's public key);  */   
    memcpy(Salt, S, S_siz);
    BLAKE2B_INIT((uint8_t*)pubkey, pubkey_siz, 0, 64, (Salt + 8) );
         					 
    /* Copy the passed password buffer into Argon2 password parameter. */
    memcpy(P, pass_txt, pass_len);
    
    prms.P = P;
    printf("prms.P is %s\n", prms.P);
    prms.S = Salt;

    prms.len_P = pass_len;
    prms.len_S = 8+64; /* 8 byte string + blake2b{64}(public_key) */
    prms.len_K = 0 ;   /* unused here. */
    prms.len_X = 0;    /* unused here. */
    
    uint8_t* argon2_output_tag = malloc(prms.T);
	memset(argon2_output_tag, 0x00, prms.T);
	
    Argon2_MAIN(&prms, argon2_output_tag);
 

    printf("\n\n***** LOGIN ARGON2id produced %lu-byte Tag: *****\n\n", prms.T);
    
    for(uint32_t i = 0; i < prms.T; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)argon2_output_tag[i]);
    }
    printf("\n\n");

    
    
    /* This is the saved encrypted private key now. */
    uint8_t* plaintext = (uint8_t*)encr_privkey;
                      
    uint32_t msg_len = encr_privkey_siz; /* 40 bytes right now */
    
    /* 32 bytes is the key length for ChaCha20. output taglen T = 64, so T/2. */                  
    uint32_t* key = (uint32_t*)(argon2_output_tag + (uint64_t)(prms.T / 2));
    
    /* NOTE: nonce_len and key_len are measured in number of uint32_t's!! */
    
    uint8_t key_len = 8; /* ChaCha20 key is always 32 (8*4) bytes */

    uint8_t nonce_len = 4;
    
    uint8_t* cyphertext = malloc(msg_len * sizeof(uint8_t));
    memset(cyphertext, 0x00, msg_len * sizeof(uint8_t));
    
    CHACHA20(plaintext, msg_len, (uint32_t*)nonce, nonce_len, key, key_len, cyphertext);
    
    printf("THE LOGIN CYPHERTEXT FROM CHACHA20 - decrypted private key:\n");
    
    for(uint32_t i = 0; i < msg_len; ++i){
        if(i % 16 == 0 && i > 0){printf("\n");}
        printf("%02x ", (uint8_t)cyphertext[i]);
    }
    printf("\n");	
		
	/* Construct bigint a from this cyphertext (decrypted private key) */
	/* Compute A' = G^a mod M */
	/* If A' == saved_pubkey, login succeeds. Else, login fails. */
	

	
	/* Temporarily write decrypted privkey to a file, then delete it. 
	 * Because the interface to easily get a corresponding public key 
	 * currently only allows to pass it as a filepath to a saved DAT file.
	 */
 	FILE* client_privkey_dat = fopen("client_privkey.dat","w");
	if(client_privkey_dat == NULL){
		printf("[ERR] - client_util.h - couldn't open client_privkey.dat\n");
		status = 1;
		goto label_cleanup_log;
	}

	size_t bytes_wr;
		         
	bytes_wr = fwrite(cyphertext, 1, encr_privkey_siz, client_privkey_dat);
	
	if(bytes_wr != encr_privkey_siz){
		printf("[ERR] - client_util.h couldnt write %u bytes to "
			   "client_privkey.dat\n", encr_privkey_siz);
		status = 1;
		goto label_cleanup_log;
	}
	
	printf("[OK] Successfully wrote %u bytes to client_privkey.dat\n"
		   ,encr_privkey_siz
	);
	
	/* Close privkey file here, not at final cleanup_reg, because gen_pub_key()
	 * also requires to open that file and read from it, irrespective of 
	 * what its callers did with that file.
	 */
	fclose(client_privkey_dat);
	
	
	/* DONE generating user's private key. */
	
	/* Step 2 - compute the user's public key and its Montgomery form. */
	
	struct bigint *pubkey_bigint;
	         
	pubkey_bigint = 
	         gen_pub_key(encr_privkey_siz, "client_privkey.dat\0", 12800);
	
	
	int del_rc;
	if( (del_rc = remove("client_privkey.dat")) != 0){
		printf("[ERR] - client_util couldn't delete PRIVKEY plain file.\n");
		status = 1;
		goto label_cleanup_log;
	}
	
	
	printf("Now comparing the password-derived pubkey with saved one.\n");
	

	/* for each byte */
	for(uint32_t i = 0; i < pubkey_siz; ++i){
		printf( "[i=%u] %02x : %02x \n"
			    , i, pubkey_bigint->bits[i], (uint8_t)pubkey[i]
			);
		if(pubkey_bigint->bits[i] != (uint8_t)pubkey[i]){
			printf("\n\n---> Public keys don't match. Wrong password. <---\n");
			printf("\n at i = %u\n\n", i);
			status = 1;
			break;
		}
	}

	/* If all bytes are the same, login successful, status = 0. */
	
	/* Different things will need to be cleaned up depending on whether we
	 * arrived here due to an error or by natural code flow. Hence the checking.
	 */

label_cleanup_log:

    if(saved)					{fclose(saved);}	  	
	if(P)				       	{free(P);}
	if(Salt)					{free(Salt);}
	if(argon2_output_tag)      	{free(argon2_output_tag);}
	if(cyphertext)			   	{free(cyphertext);}
	if(savefile_buf)			{free(savefile_buf);}
	
	if(status){
		printf("\n\n\n******* WARNING *******\n\n Login error!\n\n");
		printf("Look back in the log to locate the exact error [ERR] line.\n");
	}
	else{
		printf("\n\n\n****** LOGIN SUCCESSFUL!! ******\n\n\n");
	}
    return status;

}
