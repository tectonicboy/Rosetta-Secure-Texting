#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef struct block{
    uint8_t data[1024];
} block_t;

int main(){

    block_t BLOCK;
    printf("sizeof(block_t) = %lu\n", sizeof(block_t));
    memset(BLOCK.data, 0x00, 1024);

    block_t *block_ptr = &BLOCK, *next_ptr;
    
    printf("Memory address before increment: %p\n", block_ptr);
    
    next_ptr = block_ptr + 1; 

    printf("Memory address after increment: %p\n", next_ptr);
    return 1;
}
