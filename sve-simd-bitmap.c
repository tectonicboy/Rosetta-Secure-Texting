#include <stdio.h>
#include <arm_neon.h>

int main(void){
    printf(
     "***********************************************************************\n"
     "*                                                                     *\n"
     "*     --->  HELLO FROM XIAOMI PHONE - USB - ADB shell   <---          *\n"
     "*                                                                     *\n"
     "***********************************************************************\n"
    );
    printf("\n\n");
    printf("\n\n---> Cool stuff: Using ARM vector instructions for ADD!\n\n");

    /* Create vectors of 1.0f and 2.0f */
    float32x4_t v1 = vdupq_n_f32(1.0f);
    float32x4_t v2 = vdupq_n_f32(2.0f);

    /* Add them: result should be 3.0f in every lane */
    float32x4_t v3 = vaddq_f32(v1, v2);

    /* Number of lanes (NEON always has 4 for 32-bit elements) */
    uint32_t vl = 4;

    /* Store the result into an array for checking */
    float result[4];
    vst1q_f32(result, v3);

    /* Verify that every element equals 3.0f */
    int wrong = 0;

    for (uint32_t i = 0; i < vl; ++i) {
        if (result[i] != 3.0f) {
            wrong = 1;
            break;
        }
    }

    if (wrong)
        printf("WRONG\n");
    else
        printf("TRUE\n");

    return 0;
}
