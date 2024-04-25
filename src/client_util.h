void create_save(const char* pass_txt, uint16_t pass_len){
	
 	/* Step 1 - generate the user's private key. */
 	FILE* client_privkey_dat = fopen("client_privkey.dat","w");
	
	if(client_privkey_dat == NULL){
		printf("[ERROR] - client_util.h - couldn't open client_privkey.dat\n");
		return;
	}
	
	uint32_t req_key_len_bytes = 40;
	uint8_t* privkey_buf = malloc(req_key_len_bytes);
	size_t bytes_wr;
	
	gen_priv_key(req_key_len_bytes, privkey_buf);
	
	/* Turn off bit index 1 to make it guaranteed less than Q. */	   
	privkey_buf[req_key_len_bytes - 1] &= ~(1 << 7);

	bytes_wr = fwrite(privkey_buf, 1, req_key_len_bytes, client_privkey_dat);
	
	if(bytes_wr != req_key_len_bytes){
		printf("[ERROR] - client_util.h couldnt write %u bytes to "
			   "client_privkey.dat\n", req_key_len_bytes);
		return;
	}

	printf("[OK] Successfully wrote %u bytes to client_privkey.dat\n"
		   ,req_key_len_bytes
	);
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
	bytes_wr = 
	     fwrite(pubkey_bigint->bits, 1, pubkey_used_bytes, client_pubkey_dat);
	
	if(bytes_wr != pubkey_used_bytes){
		printf("[ERROR] - client_uilt.h couldn't write %u bytes to "
			   "client_pubkey.dat\n", pubkey_used_bytes);
		return;
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

	bytes_wr = 
	     fwrite(pubkey_montform->bits, 1, pubkeymont_used_bytes
	     	    ,client_pubkeymont_dat
	     	   );
	
	if(bytes_wr != pubkeymont_used_bytes){
		printf("[ERROR] - gen_pub_key couldnt write %u bytes to "
			   "client_pubkeymont.dat\n", pubkeymont_used_bytes);
		return;
	}

	printf("[OK] Successfully wrote %u bytes to client_pubkeymont.dat\n"
		   ,pubkeymont_used_bytes
		  );
	
	printf("Montgomery form of public key generated:\n");
	bigint_print_info(pubkey_montform);
	bigint_print_bits(pubkey_montform);
	
	int del_rc;
	if( (del_rc = remove("client_privkey.dat")) != 0){
		printf("[ERROR] - client_util couldn't delete PRIVKEY plain file.\n");
	}
	
	
	
	/* DONE generating user's public key and its Montgomery form. */
	
	/* Step 3.Encrypt the private key with the chosen registration password. */

}
