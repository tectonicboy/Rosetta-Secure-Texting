#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <arm_neon.h>

#define ORIG_BITMAP_WIDTH_PX  124
#define ORIG_BITMAP_HEIGHT_PX 124
#define BYTES_PER_PX          3
#define BYTES_OF_METADATA     54
#define BYTES_TOTAL_FILE_SIZE                                                 \
                (ORIG_BITMAP_WIDTH_PX * ORIG_BITMAP_HEIGHT_PX * BYTES_PER_PX) \
                + BYTES_OF_METADATA                                           \

#define INPUT_IMAGE_PATH  "/data/local/tmp/input.bmp"
#define OUTPUT_IMAGE_PATH "/data/local/tmp/output.bmp"

int main(){

    uint8_t* origin_bitmap_buf = NULL;
    uint8_t* target_bitmap_buf = NULL;

    if( (origin_bitmap_buf = calloc(1, BYTES_TOTAL_FILE_SIZE)) == NULL)
    { perror("Memory allocation for first  buffer FAILED: "); exit(1); }

    if( (target_bitmap_buf = calloc(1, BYTES_TOTAL_FILE_SIZE)) == NULL)
    { perror("Memory allocation for second buffer FAILED: "); exit(1); }
    
    FILE* origin_bitmap_fd = fopen(INPUT_IMAGE_PATH,  "r");
    FILE* target_bitmap_fd = fopen(OUTPUT_IMAGE_PATH, "w");

    if(origin_bitmap_fd == NULL){ perror("orig. pic. fopen() fail: "); exit(1);}
    if(target_bitmap_fd == NULL){ perror("targ. pic. fopen() fail: "); exit(1);}

    if( (fread(origin_bitmap_buf, 1, BYTES_TOTAL_FILE_SIZE, origin_bitmap_fd))
        < BYTES_TOTAL_FILE_SIZE
      ){ perror("orig. pic. fread() fail: "); exit(1);}

    /* ---------------------------------------------------------------------- */    
    /* Rotate the image - pixel by pixel. */

    for(uint64_t i = 0; i < ORIG_BITMAP_HEIGHT_PX; ++i){
        //printf("OUTER ROTATION LOOP: at row [%lu]\n", i);
        for(uint64_t j = 0; j < ORIG_BITMAP_WIDTH_PX; ++j){
            //printf("INNER ROTATION LOOP: at column pixel index [%lu]\n", j);
            memcpy(target_bitmap_buf + (j * BYTES_PER_PX * ORIG_BITMAP_HEIGHT_PX) 
                     + ((ORIG_BITMAP_HEIGHT_PX - 1 - i) * BYTES_PER_PX) + BYTES_OF_METADATA
                  ,origin_bitmap_buf + (i * BYTES_PER_PX * ORIG_BITMAP_WIDTH_PX) 
                     + (j * BYTES_PER_PX) + BYTES_OF_METADATA
                  ,BYTES_PER_PX
                  );
        }
    }
    
    /* Do the initial metadata bytes too. */
    for(uint64_t i = 0; i < BYTES_OF_METADATA; ++i){
        target_bitmap_buf[i] = origin_bitmap_buf[i];
    }

    int32_t* header_field_ptr;
    
    header_field_ptr  = (int32_t*)(target_bitmap_buf + (14 + 4 + 0));
    *header_field_ptr = (int32_t)ORIG_BITMAP_HEIGHT_PX;

    header_field_ptr  = (int32_t*)(target_bitmap_buf + (14 + 4 + 4));
    *header_field_ptr = (int32_t)ORIG_BITMAP_WIDTH_PX;
    
    /* ---------------------------------------------------------------------- */

    if( (fwrite(target_bitmap_buf, 1, BYTES_TOTAL_FILE_SIZE, target_bitmap_fd))
        < BYTES_TOTAL_FILE_SIZE
      ){ perror("Final fwrite() FAIL: "); exit(1); }
    
    fclose(origin_bitmap_fd);
    fclose(target_bitmap_fd);
    free(origin_bitmap_buf);
    free(target_bitmap_buf);

    return 0;
}
