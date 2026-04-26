#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <math.h>
#include <pthread.h>
#include <immintrin.h> /* _mulx_u64      in Montgomery Modular Multiplication */
#include <adxintrin.h> /* _addcarryx_u64 in Montgomery Modular Multiplication */
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>

/* SIMD zero out a memory buffer containing leftover sensitive information, with
 * steps taken to ensure the compiler does not optimize calls to it away.
 * Set optimization level to none (-O0) for this function, instruct the compiler
 * to not inline calls to it, mark the pointer to the memory buffer containing
 * sensitive information that must be zeroed out as volatile, which informs
 * the compiler that the memory it points to can be written to in ways the
 * compiler can't predict. This prevents the compiler from eliminating calls to
 * the function even if it determines that the effects of the function are not
 * utilized anywhere in the source code.
 * Things like explicit_bzero() and memset_explicit() do exist, however neither
 * seems to be easily available and they are only approximations as apparently
 * whole-program optimization at link time might still optimize them away.
 */
__attribute__((no_reorder))  __attribute__((used))
__attribute__((noinline))    __attribute__((optimize("O0")))
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
    while(i < num_bytes_to_erase){
        buf[i++] = 0;
    }
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

/* Change the printf() output color. */
void output_red(){ printf("\033[1;31m"); }
void output_yel(){ printf("\033[1;33m"); }
void output_rst(){ printf("\033[0m"); }

#define PRINT_RED(string)   "\x1b[31m"  string "\x1b[0m"
#define PRINT_BLUE(string)  "\x1b[34m" string "\x1b[0m"
#define SET_PRINT_BG_CYAN   printf("\x1b[46m");
#define SET_PRINT_BG_BLACK  printf("\x1b[40m");

/* Bitwise rolling means shifts but the erased bits go back to the start. */

#define UINT32_ROLL_LEFT(n_ptr, roll_amount) \
  *(n_ptr) = *(n_ptr) << (roll_amount) | *(n_ptr) >> (32 - (roll_amount));

#define UINT64_ROLL_LEFT(n_ptr, roll_amount) \
  *(n_ptr) = *(n_ptr) << (roll_amount) | *(n_ptr) >> (64 - (roll_amount));

#define UINT32_ROLL_RIGHT(n_ptr, roll_amount) \
  *(n_ptr) = *(n_ptr) >> (roll_amount) | *(n_ptr) << (32 - (roll_amount));

#define UINT64_ROLL_RIGHT(n_ptr, roll_amount) \
  *(n_ptr) = *(n_ptr) >> (roll_amount) | *(n_ptr) << (64 - (roll_amount));

/* Shorthands to fit more code on a line. */
#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s64 int64_t

/* Helper function to print the raw byte values of a memory buffer. */
void print_buffer(uint8_t* buf, uint64_t len){
    printf("\n\n");
    for(u64 x = 0; x < len; ++x){
        if(x % 16 == 0 && x > 0){printf("\n");}
        printf("%02X ", buf[x]);
    }
    printf("\n\n");
    return;
}

/* List of packet ID magic constants for legitimate recognized packet types. */
#define PACKET_ID_00 0xAD0084FF0CC25B0E
#define PACKET_ID_01 0xE7D09F1FEFEA708B
#define PACKET_ID_02 0x146AAE4D100DAEEA
#define PACKET_ID_10 0x13C4A44F70842AC1
#define PACKET_ID_11 0xAEFB70A4A8E610DF
#define PACKET_ID_20 0x9FF4D1E0EAE100A5
#define PACKET_ID_21 0x7C8124568ED45F1A
#define PACKET_ID_30 0x9FFA7475DDC8B11C
#define PACKET_ID_40 0xCAFB1C01456DF7F0
#define PACKET_ID_41 0xDC4F771C0B22FDAB
#define PACKET_ID_50 0x41C20F0BB4E34890
#define PACKET_ID_51 0x2CC04FBEDA0B5E63
#define PACKET_ID_60 0x0A7F4E5D330A14DD

/* Commonly used constants, file paths and helper macros. */
#define PRIVKEY_LEN              40
#define PUBKEY_LEN               384
#define MAX_CLIENTS              64
#define MAX_PEND_MSGS            64
#define MAX_CHATROOMS            64
#define MAX_MSG_LEN              131072
#define MAX_TXT_LEN              1024
#define SMALL_FIELD_LEN          8
#define TEMP_BUF_SIZ             16384
#define SESSION_KEY_LEN          32
#define ONE_TIME_KEY_LEN         32
#define INIT_AUTH_LEN            32
#define SHORT_NONCE_LEN          12
#define LONG_NONCE_LEN           16
#define PASSWORD_BUF_SIZ         16
#define HMAC_TRUNC_BYTES         8
#define ARGON_STRING_LEN         8
#define ARGON_HASH_LEN           64
#define ROOMMATES_ARR_SIZ        63
#define DH_M_BITWIDTH            3071
#define DH_Q_BITWIDTH            320
#define DH_G_BITWIDTH            3071
#define DH_G_MONT_BITWIDTH       3071
#define SERV_PUBKEY_BITWIDTH     3071
#define SERV_PUBKEYMONT_BITWIDTH 3071
#define SERV_PRIVKEY_BITWIDTH	   318
#define MAX_USED_BITWIDTH        12800

#define MESSAGE_LINE_LEN     (SMALL_FIELD_LEN + strlen(": \0") + MAX_TXT_LEN)
#define SIGNATURE_LEN        ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))
#define BITMASK_BIT_ON_AT(X) (1ULL << (63ULL - ((X))))

#define DEV_URANDOM_PATH       "/dev/urandom"
#define SERV_PRIVKEY_PATH      "materials/cryptography/server_privkey.dat"
#define SERV_PUBKEY_PATH       "materials/cryptography/server_pubkey.dat"
#define SERV_PUBKEYMONT_PATH   "materials/cryptography/server_pubkeymont.dat"
#define DH_MODULUS_M_PATH      "materials/cryptography/saved_M.dat"
#define DH_PRIME_ORDER_Q_PATH  "materials/cryptography/saved_Q.dat"
#define DH_GENERATOR_G_PATH    "materials/cryptography/saved_G.dat"
#define DH_G_MONT_PATH         "materials/cryptography/saved_Gm.dat"
#define RTF_LOGO_PATH          "rosetta-test-framework/rtf-logo.txt"

#define USER_SPAWNER_PROG_PATH \
	"bin/manual-user-testing/user-spawner"

#define USER_SAVEFILES_DIR \
	"rosetta-test-framework/test-accounts/"

#define AUTOMATIC_USER_SIMULATION_TEST_PROG_BASE_PATH \
	"bin/automatic-user-testing/auto-simulated-user-test-"

#define AUTOMATIC_USER_SIMULATION_AUTO_SPAWNER_BASE_PATH \
	"bin/automatic-user-testing/auto-spawner"
