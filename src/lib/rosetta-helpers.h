#pragma once

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s64 int64_t

/* Change the printf() output color. */
void output_red(){ printf("\033[1;31m"); }
void output_yel(){ printf("\033[1;33m"); }
void output_rst(){ printf("\033[0m"); }

#define PRINT_RED(string)   "\x1b[31m"  string "\x1b[0m"
#define PRINT_BLUE(string)  "\x1b[34m" string "\x1b[0m"
#define SET_PRINT_BG_CYAN   printf("\x1b[46m");
#define SET_PRINT_BG_BLACK  printf("\x1b[40m");

void print_buffer(uint8_t* buf, uint64_t len){
    printf("\n\n");
    for(u64 x = 0; x < len; ++x){
        if(x % 16 == 0 && x > 0){printf("\n");}
        printf("%02X ", buf[x]);
    }
    printf("\n\n");
    return;
}

/* Set optimization level to none (-O0) for this function, instruct the compiler
 * to not inline calls to it, mark the pointer to the memory buffer containing
 * sensitive information that must be zeroed out for security reasons as
 * volatile, which informs the compiler that the memory it points to might get
 * altered in ways the compiler can't predict, doesn't expect, and the source
 * code does not directly contain any signs it might happen. This prevents the
 * compiler from eliminating calls to the function upon determining that the
 * effects of it are not utilized anywhere in the source code. Also, attribute
 * ((used)) is another protection against the compiler optimizing away calls to
 * this function if it determines the memory it zeroes out isn't used afterward.
 *
 * Efforts by compiler writers and C language standard participants do exist
 * with functions like explicit_bzero() and memset_explicit() slowly being added
 * however, still, neither of these seems to be easily available AND they are
 * only approximations to the solution - Whole-program optimization at link time
 * might still decide to optimize them away. So, sticking to this ugliness until
 * a more elegant and straightforward way to zero out sensitive memory exists.
 */
__attribute__((no_reorder))
__attribute__((used))
__attribute__((noinline))
__attribute__((optimize("O0")))
void erase_mem_secure(volatile uint8_t* buf, uint64_t num_bytes_to_erase)
{
    __m256i zero_reg256 = _mm256_setzero_si256();
    size_t i = 0;

    /* SIMD - zero out memory in chunks of 256 bits at a time. */

    while(i + sizeof(__m256i) <= num_bytes_to_erase){
        _mm256_storeu_si256((__m256i *)(uintptr_t)(buf + i), zero_reg256);
        i += sizeof(__m256i);
    }

    /* Any remaining bytes fewer than 32, clear byte by byte. */

    while(i < num_bytes_to_erase)
        buf[i++] = 0;

    /* Compiler memory barrier to prevent aggressive compile-time and link-time
     * optimizers from reordering memory around this memory clearing operation.
     */
    __asm__ __volatile__ (
    ""          /* No assembly instructions to emit.                         */
    :           /* No output operands.                                       */
    : "r"(buf)  /* input - pointer to erased memory, in a gp register r.     */
    : "memory"  /* clobbers memory - don't reorder memory operations nearby. */
    );
    return;
}
