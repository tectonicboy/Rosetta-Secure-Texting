#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

int main(){
    FILE* fd_M_text = fopen("M_raw_string.txt", "r");
    
    if( fseek(fd_M_text, 0, SEEK_END) == -1 ){
        printf("ERROR setting file position indicator to end of file.\n");
        exit(1);
    }
    
    long int M_size_bits;
    
    if ( ( M_size_bits = ftell(fd_M_text) ) == -1 ){
        printf("ERROR reading file position indicator at end of file.\n");
        exit(1);    
    }
    
    printf("M size bits + newlines = %ld\n", M_size_bits);
    
    if( fseek(fd_M_text, 0, SEEK_SET) == -1 ){
        printf("ERROR setting file position indicator to start of file.\n");
        exit(1);
    }    
    
    printf("NOTE: Since the bits are string characters in the text file,\n"
           "      we divide by 8 to get the actual number of bytes needed.\n\n"
    );
    
    uint8_t current_byte = 0;
    uint32_t bits = 0;
    for(long int i = 0; i < (long int)(M_size_bits); ++i){
            fread(&current_byte, 1, 1, fd_M_text);
            if(current_byte == 48 || current_byte == 49){
                ++bits; 
            } 
            else if (current_byte == 10){
                printf("---> Saw a newline!!\n");
            }
            else{
                printf("---> What?? some other character??\n");
            }
    }
    
    printf("The actual bits read are: %u\n", bits);
    
    if( fseek(fd_M_text, 0, SEEK_SET) == -1 ){
        printf("ERROR setting file position indicator to start of file.\n");
        exit(1);
    }   
    
    char* M_real_bytes_buf = malloc((size_t)(bits / 8));
    memset(M_real_bytes_buf, 0x00, (size_t)(bits / 8));
    
    char current_digit = 0;
    printf("Buffer allocated with %ld bytes.\n", (long int)(bits / 8));
    
    uint32_t buf_byte_offset = 0;
    uint32_t bits_read = 0;
    uint32_t bit_in_byte = 0;
    
    uint8_t temp_byte = 0;
    
    for(long int i = 0; i < (long int)(M_size_bits); ++i){
    
        fread(&current_byte, 1, 1, fd_M_text);
        
        if(current_byte == 49 || current_byte == 48){
            if(current_byte == 49){
                temp_byte |= (1 << (7 - bit_in_byte));
            }
            
            ++bit_in_byte; 
            
            /* IF we just fille a byte. */
            if(bit_in_byte > 7){ 
                *(M_real_bytes_buf + buf_byte_offset) = temp_byte;
                temp_byte = 0;
                bit_in_byte = 0; 
                ++buf_byte_offset;
            }
                 
        }        
      
    }
    
    FILE* fd_M_bytes = fopen("M_raw_bytes.dat", "w");
    
    printf("written %lu bytes to raw binary M file.\n"
           ,fwrite(M_real_bytes_buf, 1, (size_t)(bits / 8), fd_M_bytes)
          );
     
    fclose(fd_M_text);
    fclose(fd_M_bytes);      
    return 0;
}
