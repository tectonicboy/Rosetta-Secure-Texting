#include "coreutil.h"

int main(int argc, char* argv[]){
	if(argc != 2){
		printf("Must pass 1 argument (required key size in bytes)\n"
			   "in order to generate a new server private key.\n");
		return 1;
	}
	
	uint32_t req_key_len_bytes = (uint32_t)(atoi(argv[1]));
	
	printf("Obtained req_key_bytes arg as uint32_t: %u\n", req_key_len_bytes);
	
	FILE* server_privkey_dat = fopen("server_privkey.dat","w");
	
	if(server_privkey_dat == NULL){
		printf("[ERROR] - gen_priv_key couldn't open server_privkey.dat\n");
		return 1;
	}
	
	uint8_t* privkey_buf = malloc(req_key_len_bytes);
	
	size_t bytes_wr;
	
	gen_priv_key(req_key_len_bytes, privkey_buf);
	
	/* Turn off bit index 1 to make it guaranteed less than Q. */
	printf("LAST index byte before clearing: %u\n", 
		   privkey_buf[req_key_len_bytes - 1]);
		   
	privkey_buf[req_key_len_bytes - 1] &= ~(1 << 7);

	printf("LAST index byte after clearing: %u\n", 
	   privkey_buf[req_key_len_bytes - 1]);

	bytes_wr = fwrite(privkey_buf, 1, req_key_len_bytes, server_privkey_dat);
	
	free(privkey_buf);
	
	if(bytes_wr != req_key_len_bytes){
		printf("[ERROR] - gen_priv_key couldnt write %u bytes to "
			   "server_privkey.dat\n", req_key_len_bytes);
		return 1;
	}

	printf("[OK] Successfully wrote %u bytes to server_privkey.dat\n"
		   ,req_key_len_bytes
		  );
		  
	return 0;
}
