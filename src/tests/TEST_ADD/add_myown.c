#include "../../bigint.h"

#define RES_BITS 4096

int main(){
    
    bigint one, a, b, res, max_1024_bit;
    
    char *python_exec_command = calloc(1, RES_BITS);
    
    uint8_t* python_result  = calloc(1, RES_BITS);
    uint8_t* comparable_buf = calloc(1, RES_BITS);
    
    uint64_t py_cmd_offset = 0;
    uint64_t a_used_bytes, b_used_bytes;
    uint64_t pad_zeros = 0;
    
    size_t bytes_read = 0;
    
    bigint_create(&one, RES_BITS, 1);
    bigint_create(&a,   RES_BITS, 1);
    bigint_create(&b,   RES_BITS, 1);
    bigint_create(&res, RES_BITS, 0);
    
    /* Setup the limit till which we increase the ADD operands for testing. */
    bigint_create(&max_1024_bit, RES_BITS, 0);
    memset(max_1024_bit.bits, 1, (1024/8));
    max_1024_bit.used_bits = 1024;
    max_1024_bit.free_bits = RES_BITS - 1024;
    
    /* First ADD operand from 0 to max_1024_bit */
    while(bigint_compare2(&a, &max_1024_bit) == 3){
    
        /* Second ADD operand from 0 to max_1024_bit */
        while(bigint_compare2(&b, &max_1024_bit) == 3){
            
            /* Perform the addition here and on python. */
            bigint_add_fast(&a, &b, &res);
            
            /* Construct the python execution command with its cmd line args. */
            py_cmd_offset = 0;
            
            strncpy(
                     python_exec_command
                    ,"python3 add_python.py "
                    ,strlen(strcat("python3 add_python.py ", "\0"))
                    );
                    
            py_cmd_offset += strlen(strcat("python3 add_python.py ", "\0"));
            
            /* Insert the 1st and 2nd ADD operands in little endian binary. */
            if(a.used_bits == 0){
                a_used_bytes = 1;
            }
            else{
                a_used_bytes = a.used_bits;
                while(a_used_bytes % 8 != 0){
                    ++a_used_bytes;
                }
                a_used_bytes /= 8;
            }
            
            if(b.used_bits == 0){
                b_used_bytes = 1;
            }
            else{
                b_used_bytes = b.used_bits;
                while(b_used_bytes % 8 != 0){
                    ++b_used_bytes;
                }
                b_used_bytes /= 8;
            }
            
            /* SWAP ENDIANNESS BEFORE FEEDING NUMBERS TO PYTHON AS IT'S BIGEND*/
            
            for(uint64_t i = 0; i < a_used_bytes; ++i){
                for(uint64_t j = 0; j < 8; ++j){
                    if( (a.bits[i]) & (1 << (7-j))){
                        python_exec_command[py_cmd_offset] = '1';
                    }
                    else{
                        python_exec_command[py_cmd_offset] = '0';
                    }
                    ++py_cmd_offset;
                }
            }
            
            python_exec_command[py_cmd_offset] = ' ';
            ++py_cmd_offset;
            
            for(uint64_t i = 0; i < b_used_bytes; ++i){
                for(uint64_t j = 0; j < 8; ++j){
                    if( (b.bits[i]) & (1 << (7-j))){
                        python_exec_command[py_cmd_offset] = '1';
                    }
                    else{
                        python_exec_command[py_cmd_offset] = '0';
                    }
                    ++py_cmd_offset;
                }
            }
            
            printf("Constructed the python execute command with arguments:\n");
            printf("%s\n", python_exec_command);
            
            system(python_exec_command);
            
            /* Grab python's result and compare it with the BigInt library's */
            FILE* py_res_file = fopen("python_add_result.txt", "r");

            fseek(py_res_file, 2, SEEK_SET);

            memset(python_result, 0x00, RES_BITS);

            bytes_read = fread(python_result, 1, RES_BITS, py_res_file);

            fclose(py_res_file);
            
            pad_zeros = bytes_read % 8;
            /* Python's results are BIG ENDIAN so pad 0s at leftmost spaces */
            
            /* Then use bigint library's Switch Endianness facility. */

       
            /* Increment second operand at the end. */
            bigint_add_fast(&b, &one, &res);
            bigint_equate2(&b, &res);
        } 
        /* Reset second operand back to 0. */
        bigint_nullify(&b);
        
    
        /* Increment first operand at the end. */
        bigint_add_fast(&a, &one, &res);
        bigint_equate2(&a, &res);
    }
    
    return 0;   


}
