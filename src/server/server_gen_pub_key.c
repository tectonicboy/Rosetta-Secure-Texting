#include "../lib/coreutil.h"

int main(int argc, char* argv[]){
    if(argc != 2){
        printf("Must pass 1 argument (size in bytes of private key)\n"
               "in order to generate a new server public key.\n");
        return 1;
    }
    
    uint32_t privkey_len_bytes = (uint32_t)(atoi(argv[1]));
    
    printf("Obtained privkey_len_bytes arg: %u\n", privkey_len_bytes);

    struct bigint *pubkey_bigint
                 ,*pubkey_montform = malloc(sizeof(struct bigint))
                 ,*M
                 ;
                 
     M = get_bigint_from_dat
      ( 3072
       ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_M.dat"
       ,3071
       ,12800
      );
                 
    bigint_create(pubkey_montform, 12800, 0);
    
    pubkey_bigint = 
             gen_pub_key(privkey_len_bytes, "server_privkey.dat", 12800);
    
    uint32_t pubkey_used_bytes = pubkey_bigint->used_bits;
    
    while(pubkey_used_bytes % 8){
        ++pubkey_used_bytes;
    }
    pubkey_used_bytes /= 8;
    
    FILE* server_pubkey_dat = fopen("server_pubkey.dat","w");
    size_t bytes_wr;
    bytes_wr = 
         fwrite(pubkey_bigint->bits, 1, pubkey_used_bytes, server_pubkey_dat);
    
    if(bytes_wr != pubkey_used_bytes){
        printf("[ERROR] - gen_pub_key couldnt write %u bytes to "
               "server_pubkey.dat\n", pubkey_used_bytes);
        return 1;
    }

    printf("[OK] Successfully wrote %u bytes to server_pubkey.dat\n"
           ,pubkey_used_bytes
          );
          
    printf("\nNow generating Montgomery form of this public key.\n");
    
    get_mont_form(pubkey_bigint, pubkey_montform, M);
    
    
    uint32_t pubkeymont_used_bytes = pubkey_montform->used_bits;
    
    while(pubkeymont_used_bytes % 8){
        ++pubkeymont_used_bytes;
    }
    pubkeymont_used_bytes /= 8;
    
    FILE* server_pubkeymont_dat = fopen("server_pubkeymont.dat","w");

    bytes_wr = 
         fwrite(pubkey_montform->bits, 1, pubkeymont_used_bytes
                 ,server_pubkeymont_dat
                );
    
    if(bytes_wr != pubkeymont_used_bytes){
        printf("[ERROR] - gen_pub_key couldnt write %u bytes to "
               "server_pubkeymont.dat\n", pubkeymont_used_bytes);
        return 1;
    }

    printf("[OK] Successfully wrote %u bytes to server_pubkeymont.dat\n"
           ,pubkeymont_used_bytes
          );
    
    printf("Montgomery form of public key generated:\n");
    bigint_print_info(pubkey_montform);
    bigint_print_bits(pubkey_montform);
    
    return 0;
}
