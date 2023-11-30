#include "../bigint.h"

#define MAX_BITLEN 256 

   /*********************************************************************************
    *                                                                               *                               
    *  TEST FILE for BigInt library's MULTIPLICATION algorithm.                     *
    *                                                                               *
    *  TESTS:  (All numbers will have 256 reserved bits)                            *
    *     ==================================================================        *   
    *         0 * 0 = 0,   0 * 1 = 0,   1 * 0 = 0,    1 * 1 = 1;                    *  
    *                                                                               *
    *         2048 * 0 = 0;  0 * 2048 = 0;    1 * 2048 = 2048,  2048 * 1 = 2048;    *
    *                                                                               *
    *         2048 * 115 =  235,520; 235,520 * 235,520 =  55,469,670,400            *
    *                                                                               *  
    *         1,000,000,000 * 1,000,000,000 = 1,000,000,000,000,000,000;            *
    *                                                                               *                                                                               
    *                                                                               * 
    *         1,248,999,256 * 74,985 =  93,656,209,211,160;                         *
    *     ===================================================================       *
    *         93,656,209,211,160 * 1,000,000,000,000,000,000                        *
    *         = 93,565,209,211,160,000,000,000,000,000,000                          *
    *     ===================================================================       *
    *    55,469,670,400 * 93,656,209,211,160 = 5,195,079,055,856,489,201,664,000    *
    *     ===================================================================       *
    *   5,195,079,055,856,489,201,664,000                                           *                                    
    * * 93,565,209,211,160,000,000,000,000,000,000    (Result needs 189 bits)       *                                       
    * = 486,078,658,729,727,979,594,591,567,599,370,240,000,000,000,000,000,000,000 *                                                                             *      
    *********************************************************************************           
    */
    
int main(){
    struct bigint 
      zero
     ,one
     ,N1 /* 2048 */
     ,N2 /* 115 */
     ,N3 /* 1,000,000,000 */
     ,N4 /* 1,248,999,256 */
     ,N5 /* 74,958 */
      
     ,R0 /* 0 and 1 */            
     ,R1 /* 235,520 */    
     ,R2 /* 55,469,670,400 */
     ,R3 /* 1,000,000,000,000,000,000 */
     ,R4 /* 93,656,209,211,160 */
     ,R5 /* 93,656,209,211,160,000,000,000,000,000,000 */
     ,R6 /* 5,195,079,055,856,489,201,664,000 */
     ,R7 /* 486,551,410,923,810,920,111,942,991,599,370,240,000,000,000,000,000,000,000 */    
     ;           
           
     
    bigint_create(&zero, MAX_BITLEN, 0         );
    bigint_create(&one,  MAX_BITLEN, 1         ); 
    bigint_create(&N1,   MAX_BITLEN, 2048      );
    bigint_create(&N2,   MAX_BITLEN, 115       );
    bigint_create(&N3,   MAX_BITLEN, 1000000000);
    bigint_create(&N4,   MAX_BITLEN, 1248999256);
    bigint_create(&N5,   MAX_BITLEN, 74985     );
    
    bigint_create(&R0,   MAX_BITLEN, 0);
    bigint_create(&R1,   MAX_BITLEN, 0);     
    bigint_create(&R2,   MAX_BITLEN, 0);
    bigint_create(&R3,   MAX_BITLEN, 0);     
    bigint_create(&R4,   MAX_BITLEN, 0);
    bigint_create(&R5,   MAX_BITLEN, 0);     
    bigint_create(&R6,   MAX_BITLEN, 0);
    bigint_create(&R7,   MAX_BITLEN, 0);     
     
     
     
    bigint_mul2(&zero, &zero, &R0);
    output_yel(); printf("\n^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&zero, &one,  &R0);   
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&one,  &zero, &R0);   
    output_yel(); printf("^^^ Expected: 0 ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&one,  &one,  &R0);    
    output_yel(); printf("^^^ Expected: 1  ^^^\n\n"); output_rst();
    
    
    
    
    bigint_mul2(&N1,   &zero, &R0);
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&zero, &N1,   &R0);
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&one,  &N1,   &R0);
    output_yel(); printf("\n^^^ Expected: N1  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&N1,   &one,  &R0);
    output_yel(); printf("^^^ Expected: N1  ^^^\n\n"); output_rst();
    
       
     
    
    bigint_mul2(&N1, &N2, &R1);
    output_yel(); printf("^^^ Expected: R1  ^^^\n\n"); output_rst();
    
    
    bigint_mul2(&R1, &R1, &R2);
    output_yel(); printf("^^^ Expected: R2  ^^^\n\n"); output_rst();
    
    
    
    bigint_mul2(&N3, &N3, &R3);
    output_yel(); printf("^^^ Expected: R3  ^^^\n\n"); output_rst();
    
    bigint_mul2(&N4, &N5, &R4);
    output_yel(); printf("^^^ Expected: R4  ^^^\n\n"); output_rst();
    
    bigint_mul2(&R3, &R4, &R5);
    output_yel(); printf("^^^ Expected: R5  ^^^\n\n"); output_rst();
    
    bigint_mul2(&R2, &R4, &R6);
    output_yel(); printf("^^^ Expected: R6  ^^^\n\n"); output_rst();
    
    bigint_mul2(&R5, &R6, &R7);
    output_yel(); printf("^^^ Expected: R7  ^^^\n\n"); output_rst(); 
     
     
     
     
     
     
     
     
     
                
}           
