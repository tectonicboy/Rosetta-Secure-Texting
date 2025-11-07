#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <arm_neon.h>
#include <math.h>

#define WIDTH_PX          1920
#define HEIGHT_PX         1280
#define PX_SIZ            3
#define HDR_SIZ           138
#define HDR_WIDTH_OFFSET  (14 + 4 + 0)
#define HDR_HEIGHT_OFFSET (14 + 4 + 4)
#define FILE_SIZ          (WIDTH_PX * HEIGHT_PX * PX_SIZ) + HDR_SIZ

#define INPUT_IMAGE_PATH  "/data/local/tmp/input.bmp"
#define OUTPUT_IMAGE_PATH "/data/local/tmp/output.bmp"

int main(){

    uint8_t* bitmap = NULL;

    if( (bitmap = calloc(1, FILE_SIZ)) == NULL)
    { perror("Memory allocation for first  buffer FAILED: "); exit(1); }
 
    FILE* origin_bitmap_fd = fopen(INPUT_IMAGE_PATH,  "r");
    FILE* target_bitmap_fd = fopen(OUTPUT_IMAGE_PATH, "w");

    if(origin_bitmap_fd == NULL){ perror("orig. pic. fopen() fail: "); exit(1);}
    if(target_bitmap_fd == NULL){ perror("targ. pic. fopen() fail: "); exit(1);}

    if( (fread(bitmap, 1, FILE_SIZ, origin_bitmap_fd))
        < FILE_SIZ
      ){ perror("orig. pic. fread() fail: "); exit(1);}

    int64_t W = WIDTH_PX, H = HEIGHT_PX;
    int64_t O, S, T, Q, R;
    uint8_t AUX1_1, AUX1_2, AUX1_3;
 
    uint8_t indices_bitmask[ (size_t)ceil( ((double)(W * H)) / 8.0) ];

    for(S = 0; S < W * H; ++S){
        if( indices_bitmask[(size_t)floor(((double)S) / 8.0)]
              & (1 << (8 - (S % 8) - 1)) )
        { continue; }

        O = S;

        AUX1_1 = bitmap[(S * PX_SIZ) + 0 + HDR_SIZ];
        AUX1_2 = bitmap[(S * PX_SIZ) + 1 + HDR_SIZ];
        AUX1_3 = bitmap[(S * PX_SIZ) + 2 + HDR_SIZ];

        /* Find sequence index (each having H pixels) and offset into it. */

label_sequence_continues:

        Q = floor(S/H);
        R = S % H;

        /* Find target index for this source index. */

        T = ((H-1)*W) - (Q * (H-1)) - (R * (W+1));
        T = S + T;

        indices_bitmask[(size_t)floor(((double)S) /8.0)] |= 
                                                  ((uint8_t)1) << (8-(S % 8)-1);

        /* Put source pixel data into target pixel. */

        if( __builtin_expect(T != O, 1) ){

            memcpy( bitmap + (S * PX_SIZ) + HDR_SIZ
                   ,bitmap + (T * PX_SIZ) + HDR_SIZ
                   ,PX_SIZ
                  );
          
            /*
            bitmap[(S * PX_SIZ) + 0 + HDR_SIZ] =
                                         bitmap[(T * PX_SIZ) + 0 + HDR_SIZ];

            bitmap[(S * PX_SIZ) + 1 + HDR_SIZ] =
                                         bitmap[(T * PX_SIZ) + 1 + HDR_SIZ];

            bitmap[(S * PX_SIZ) + 2 + HDR_SIZ] =
                                         bitmap[(T * PX_SIZ) + 2 + HDR_SIZ];
            */
        }
        else{
            bitmap[(S * PX_SIZ) + 0 + HDR_SIZ] = AUX1_1;
            bitmap[(S * PX_SIZ) + 1 + HDR_SIZ] = AUX1_2;
            bitmap[(S * PX_SIZ) + 2 + HDR_SIZ] = AUX1_3;
        }

        S = T;

        if( __builtin_expect (S != O, 1) )
            goto label_sequence_continues;

        else
            continue;
    }

    /* ---------------------------------------------------------------------- */

    /* Do the initial metadata bytes too. */

    int32_t* header_field_ptr;
    
    header_field_ptr  = (int32_t*)(bitmap + HDR_WIDTH_OFFSET);
    *header_field_ptr = (int32_t)HEIGHT_PX;

    header_field_ptr  = (int32_t*)(bitmap + HDR_HEIGHT_OFFSET);
    *header_field_ptr = (int32_t)WIDTH_PX;
    
    /* ---------------------------------------------------------------------- */

    if( (fwrite(bitmap, 1, FILE_SIZ, target_bitmap_fd)) < FILE_SIZ ){
        perror("Final fwrite() FAIL: "); 
        exit(1);
    }

    fclose(origin_bitmap_fd);
    fclose(target_bitmap_fd);

    return 0;
}

