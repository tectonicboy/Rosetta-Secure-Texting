#include "../bigint.h"

#define MAX_BITLEN 512

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
     
     
     
    bigint_mul_fast(&zero, &zero, &R0);
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);
    output_yel(); printf("\n^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&zero, &one,  &R0);   
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);    
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&one,  &zero, &R0);   
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);     
    output_yel(); printf("^^^ Expected: 0 ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&one,  &one,  &R0);    
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);      
    output_yel(); printf("^^^ Expected: 1  ^^^\n\n"); output_rst();
    
    
    
    
    bigint_mul_fast(&N1,   &zero, &R0);
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);      
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&zero, &N1,   &R0);
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);      
    output_yel(); printf("^^^ Expected: 0  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&one,  &N1,   &R0);
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);      
    output_yel(); printf("\n^^^ Expected: 2048  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&N1,   &one,  &R0);
    bigint_print_info(&R0);
    bigint_print_all_bits(&R0);      
    output_yel(); printf("^^^ Expected: 2048  ^^^\n\n"); output_rst();
    
       
     
    
    bigint_mul_fast(&N1, &N2, &R1);
    bigint_print_info(&R1);
    bigint_print_all_bits(&R1);      
    output_yel(); printf("^^^ Expected: 235,520  ^^^\n\n"); output_rst();
    
    
    bigint_mul_fast(&R1, &R1, &R2);
    bigint_print_info(&R2);
    bigint_print_all_bits(&R2);      
    output_yel(); printf("^^^ Expected: 55,469,670,400  ^^^\n\n"); output_rst();
    
    
    
    bigint_mul_fast(&N3, &N3, &R3);
    bigint_print_info(&R3);
    bigint_print_all_bits(&R3);      
    output_yel(); printf("^^^ Expected: 1,000,000,000,000,000,000   ^^^\n\n"); output_rst();
    
    bigint_mul_fast(&N4, &N5, &R4);
    bigint_print_info(&R4);
    bigint_print_all_bits(&R4);      
    output_yel(); printf("^^^ Expected: 93,656,209,211,160  ^^^\n\n"); output_rst();
    
    bigint_mul_fast(&R3, &R4, &R5);
    bigint_print_info(&R5);
    bigint_print_all_bits(&R5);      
    output_yel(); printf("^^^ Expected: 93,656,209,211,160,000,000,000,000,000,000  ^^^\n\n"); output_rst();
    
    bigint_mul_fast(&R2, &R4, &R6);
    bigint_print_info(&R6);
    bigint_print_all_bits(&R6);      
    output_yel(); printf("^^^ Expected: 5,195,079,055,856,489,201,664,000  ^^^\n\n"); output_rst();
    
    bigint_mul_fast(&R5, &R6, &R7);
    bigint_print_info(&R7);
    bigint_print_all_bits(&R7);      
    output_yel(); printf("^^^ Expected: 486,551,410,923,810,920,111,942,991,599,370,240,000,000,000,000,000,000,000  ^^^\n\n"); output_rst(); 
     
     
     
     
     
     
     
     
     
                
}           
