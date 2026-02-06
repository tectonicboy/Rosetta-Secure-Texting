#include <signal.h>
#include <errno.h>

#include <sys/time.h>
#include <time.h>

/* All bitmasks are 64-bit and begin with their leftmost bit. */

#define BITMASK_BIT_ON_AT(X) (1ULL << (63ULL - ((X))))

#define SERVER_PORT      54746
#define PRIVKEY_LEN      40
#define PUBKEY_LEN       384
#define MAX_CLIENTS      64
#define MAX_PEND_MSGS    64
#define MAX_CHATROOMS    64
#define MAX_MSG_LEN      131072
#define MAX_TXT_LEN      1024
#define MAX_SOCK_QUEUE   1024
#define MAX_BIGINT_SIZ   12800
#define SMALL_FIELD_LEN  8
#define TEMP_BUF_SIZ     16384
#define SESSION_KEY_LEN  32
#define ONE_TIME_KEY_LEN 32
#define INIT_AUTH_LEN    32
#define SHORT_NONCE_LEN  12
#define LONG_NONCE_LEN   16
#define PASSWORD_BUF_SIZ 16
#define HMAC_TRUNC_BYTES 8
#define ARGON_STRING_LEN 8
#define ARGON_HASH_LEN   64
#define MESSAGE_LINE_LEN (SMALL_FIELD_LEN + 2 + MAX_TXT_LEN)
#define SIGNATURE_LEN    ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))

u8 temp_handshake_memory_region_isLocked = 0;

struct roommate{
    char   guest_user_id[SMALL_FIELD_LEN];
    bigint guest_pubkey;
    bigint guest_pubkey_mont;
    u8*    guest_KBA;
    u8*    guest_KAB;
    u8*    guest_Nonce;
    u64    guest_nonce_counter;
};

#define roommates_arr_siz 63

struct roommate roommates[roommates_arr_siz];

u64 next_free_roommate_slot = 0;
u64 num_roommates = 0;

/* Bit i = 1 means client slot [i] in the global descriptor array of structures
 *           is currently in use by a connected client and unavailable.
 *           Currently only bits 0 to 62 can be used.
 */
u64 roommate_slots_bitmask = 0;

/* Bit i = 1 means we use session key KAB to send stuff to the i-th client and
 *           session key KBA to receive stuff from them. 0 means the opposite.
 *           Only usable if the i-th global descriptor is currently in use.
 */
u64 roommate_key_usage_bitmask = 0;

/* It could be in 2 states of fullness when we clear it, because our login
 * attempt could be rejected after we send msg_00 OR after we send msg_01.
 * The two functions that send these messages both fill out the handshake
 * memory region with different things, including pointers to heap memory,
 * which is why we need to keep track of what was placed in the handshake
 * memory region at the point of zeroing it out and releasing it.
 */
u8 handshake_memory_region_state = 0;

u64  own_ix = 0;
unsigned char own_user_id[SMALL_FIELD_LEN];

u64 server_nonce_counter = 0;
/* thread_ID of main thread allows poller thread to send it a signal, in order
 * to interrupt its blocked scanf(), if it's told the room owner has closed it.
 * and thus the client shouldn't be allowed to send any more messages in it.
 */
pthread_t main_thread_id;
pthread_t poller_threadID;
pthread_mutex_t mutex;
pthread_mutex_t poll_mutex;

volatile uint8_t texting_should_stop = 0;

u8 own_privkey_buf[PRIVKEY_LEN];

bigint server_shared_secret;
bigint server_nonce_bigint;
bigint *M  = NULL;
bigint *Q  = NULL;
bigint *G  = NULL;
bigint *Gm = NULL;
bigint *server_pubkey = NULL;
bigint server_pubkey_mont;
bigint own_privkey;
bigint own_pubkey;

/* These are for talking securely to the Rosetta server only. */
u8 *KAB;
u8 *KBA;

/* Memory region holding short-term cryptographic artifacts for Login scheme. */
u8 temp_handshake_buf[TEMP_BUF_SIZ];

/* List of packet ID magic constats for legitimate recognized packet types. */
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

/* Validate a cryptographic signature computed by the Rosetta server. */
u8 authenticate_server(u8* signed_ptr, u64 signed_len, u64 sign_offset){

    bigint *recv_e;
    bigint *recv_s;

    u64 s_offset = sign_offset;
    u64 e_offset = (sign_offset + sizeof(bigint) + PRIVKEY_LEN);

    u8 status = 0;

    /* Reconstruct the sender's signature as the two BigInts that make it up. */
    recv_s = (bigint*)(signed_ptr + s_offset);
    recv_e = (bigint*)(signed_ptr + e_offset);

    recv_s->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    recv_e->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);

    memcpy( recv_s->bits
           ,signed_ptr + (sign_offset + sizeof(bigint))
           ,PRIVKEY_LEN
    );

    memcpy( recv_e->bits
           ,signed_ptr + (sign_offset + (2*sizeof(bigint)) + PRIVKEY_LEN)
           ,PRIVKEY_LEN
    );

    /* Verify the sender's cryptographic signature. */
    status = signature_validate(
        Gm, &server_pubkey_mont, M, Q, recv_s, recv_e, signed_ptr, signed_len
    );

    bigint_cleanup(recv_s);
    bigint_cleanup(recv_e);

    return status;
}

/* A user requested to be logged in Rosetta:

    Client ----> Server

================================================================================
|        PACKET_ID_00         |   Client's short-term public key in the clear  |
|=============================|================================================|
|       SMALL_FIELD_LEN       |                    PUBKEY_LEN                  |
--------------------------------------------------------------------------------

*/
u8 construct_msg_00(u8** msg_buf, u64* msg_len){

    bigint* A_s;
    bigint temp_privkey;

    u8 status = 0;

    *msg_len = SMALL_FIELD_LEN + PUBKEY_LEN;

    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    /* Manual construction of a BigInt - UGLY!! Add to the Library when time. */

    temp_privkey.bits = (u8*)calloc(1, MAX_BIGINT_SIZ);

    /* Generate a short-term pair of private and public keys, store them in the
     * designated handshake memory region and send the short-term public key
     * to the Rosetta server in the clear, so it can generate a short-term
     * DH shared secret with us. On reply, it sends us its own short-term
     * public key (now that it knows a user is trying to log in) and we can
     * compute the same short-term DH shared secret as well, in process_msg_00.
     */
    temp_handshake_memory_region_isLocked = 1;

    gen_priv_key(PRIVKEY_LEN, temp_handshake_buf);

    memcpy(temp_privkey.bits, temp_handshake_buf, PRIVKEY_LEN);
    temp_privkey.size_bits = MAX_BIGINT_SIZ;
    temp_privkey.used_bits = get_used_bits(temp_handshake_buf, PRIVKEY_LEN);

    memset(temp_handshake_buf, 0, PRIVKEY_LEN);

    memcpy(temp_handshake_buf, &temp_privkey, sizeof(bigint));


    /* Interface generating a pub_key still needs priv_key in a file. TODO. */
    save_bigint_to_dat("temp_privkey_DAT.dat", &temp_privkey);

    A_s = gen_pub_key(PRIVKEY_LEN, "temp_privkey_DAT.dat", MAX_BIGINT_SIZ);

    /* Place our short-term pub_key also in the locked memory region. */
    memcpy(temp_handshake_buf + sizeof(bigint), A_s, sizeof(bigint));

    handshake_memory_region_state = 1;

    /* Construct and send the MSG buffer to the TCP server. */

    u64 packet_id00 = PACKET_ID_00;
    memcpy(*msg_buf, &packet_id00, SMALL_FIELD_LEN);

    memcpy((*msg_buf) + SMALL_FIELD_LEN, A_s->bits, PUBKEY_LEN);


/* Unused for now, but on error from a library call, set STATUS + jump here. */
/* For now the code path just naturally reaches this cleanup code.           */
label_cleanup:

    system("rm temp_privkey_DAT.dat");
    free(A_s);

    return status;
}

/* Server sent its short-term public key too, so the client can now compute a
   shared secret and transport its LONG-TERM public key in encrypted form and
   obtain its user index, completing the login handshake.

    Server ----> Client

================================================================================
| PACKET_ID_00 | Server's one time PubKey | Signature of unused part of X: Y_s |
|==============|==========================|====================================|
|  SMALL_LEN   |       PUBKEY_LEN         |             SIGNATURE_LEN          |
--------------------------------------------------------------------------------

*/
u8 process_msg_00(u8* received_buf, u8** msg_01_buf, u64* msg_01_len){

    u64* aux_ptr64_tempbuf = NULL;
    u64  handshake_buf_key_offset;
    u64  handshake_buf_nonce_offset;
    u64  packet_id01 = PACKET_ID_01;

    const u64 B = 64;
    const u64 L = 64;

    u32 tempbuf_write_offset;
    u32 shared_secret_read_offset;
    u32 HMAC_reply_offset = SMALL_FIELD_LEN + PUBKEY_LEN;

    bigint  X_s;
    bigint  B_s;
    bigint  B_sM;
    bigint  zero;
    bigint *a_s = (bigint*)(temp_handshake_buf);

    u8 status = 0;
    u8 K0[B];
    u8 ipad[B];
    u8 opad[B];
    u8 K0_XOR_ipad_TEXT[B + PUBKEY_LEN];
    u8 BLAKE2B_output[L];
    u8 last_BLAKE2B_input[B + L];
    u8 K0_XOR_ipad[B];
    u8 K0_XOR_opad[B];
    u8 auth_status;
    u8 auth_buf[INIT_AUTH_LEN + SIGNATURE_LEN];

    *msg_01_len = SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES;

    free(*msg_01_buf);
    *msg_01_buf = (u8*)(void*)calloc(1, *msg_01_len);

    memset(K0,                  0, B);
    memset(ipad,                0, B);
    memset(opad,                0, B);
    memset(K0_XOR_ipad_TEXT,    0, B + PUBKEY_LEN);
    memset(BLAKE2B_output,      0, L);
    memset(last_BLAKE2B_input,  0, B + L);
    memset(K0_XOR_ipad,         0, B);
    memset(K0_XOR_opad,         0, B);
    memset(auth_buf,            0, INIT_AUTH_LEN + SIGNATURE_LEN);

    /* Grab the server's short-term public key from the transmission.        */
    /* Another bigint construction by hand, ugly!! Find time for a function. */
    B_s.bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    memcpy(B_s.bits, received_buf + SMALL_FIELD_LEN, PUBKEY_LEN);
    B_s.size_bits = MAX_BIGINT_SIZ;
    B_s.used_bits = get_used_bits(B_s.bits, PUBKEY_LEN);

    /* Compute a short-term shared secret with the server, extract a pair of
     * symmetric bidirectional keys and the symmetric ChaCha Nonce, as well as
     * the unused part of the shared secret, of which the server has computed
     * a cryptographic signature, which we need to verify for authentication.
     *
     *       X_s   = B_s^a_s mod M   <--- Ephemeral shared secret with server.
     *
     *       KAB_s = X_s[0  .. 31 ]
     *       KBA_s = X_s[32 .. 63 ]
     *       Y_s   = X_s[64 .. 95 ]
     *       N_s   = X_s[96 .. 107]  <--- 12-byte Nonce for ChaCha20.
     */

    bigint_create_from_u32(&X_s,  MAX_BIGINT_SIZ, 0);
    bigint_create_from_u32(&zero, MAX_BIGINT_SIZ, 0);
    bigint_create_from_u32(&B_sM, MAX_BIGINT_SIZ, 0);

    get_mont_form(&B_s, &B_sM, M);

    /* Check the other side's public key for security flaws and consistency. */
    if(   ((bigint_compare2(&zero, &B_s)) != CMP_SECOND_BIGGER)
        ||
          ((bigint_compare2(M, &B_s)) != CMP_FIRST_BIGGER)
        //||
        // (check_pubkey_form(&B_sM, M, Q) == 1)
      )
    {
        printf("[ERR] Client: Server's short-term public key is invalid.\n");
        printf("              Its info and ALL %u bits:\n\n", B_s.size_bits);
        bigint_print_info(&B_s);
        bigint_print_all_bits(&B_s);
        status = 1;
        goto label_cleanup;
    }

    /* X_s = B_s^a_s mod M */
    mont_pow_mod_m(&B_sM, a_s, M, &X_s);

    /* Construct a special buffer containing Y_s concatenated with the received
     * signature, because the signature validating interface needs it that way
     * because that's how most use cases of it have their buffers structured -
     * the signature to be validated is in the same memory buffer as what was
     * signed to begin with.
     */
    memcpy( auth_buf
           ,X_s.bits + (2 * SESSION_KEY_LEN)
           ,INIT_AUTH_LEN
          );

    memcpy( auth_buf + INIT_AUTH_LEN
           ,received_buf  + (SMALL_FIELD_LEN + PUBKEY_LEN)
           ,SIGNATURE_LEN
          );

    /* Validate the signature of the unused part of the shared secret, Y_s. */
    auth_status = authenticate_server(auth_buf, INIT_AUTH_LEN, INIT_AUTH_LEN);

    if(auth_status == 1){
        printf("[ERR] Client: Invalid signature in process_msg_00. Drop.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Transport the 2 symmetric keys, server's one-time public key and the
     * 2 cryptographic artifacts (N, Y) to the designated locked memory region.
     */

    tempbuf_write_offset      = 2 * sizeof(bigint);
    shared_secret_read_offset = 0;

    /* Key B_s */
    memcpy(temp_handshake_buf + tempbuf_write_offset, &B_s, sizeof(bigint));

    tempbuf_write_offset += sizeof(bigint);

    handshake_memory_region_state = 2;

    /* Key KAB_s */
    memcpy( temp_handshake_buf + tempbuf_write_offset
           ,X_s.bits
           ,SESSION_KEY_LEN
          );

    shared_secret_read_offset += SESSION_KEY_LEN;
    tempbuf_write_offset      += SESSION_KEY_LEN;

    /* Key KBA_s */
    memcpy( temp_handshake_buf + tempbuf_write_offset
           ,X_s.bits + shared_secret_read_offset
           ,SESSION_KEY_LEN
          );

    shared_secret_read_offset += SESSION_KEY_LEN;
    tempbuf_write_offset      += SESSION_KEY_LEN;

    /* Section of shared secret on which we'll compute Schnorr signatures. */
    memcpy( temp_handshake_buf + tempbuf_write_offset
        ,X_s.bits + shared_secret_read_offset
        ,INIT_AUTH_LEN
       );

    shared_secret_read_offset += INIT_AUTH_LEN;
    tempbuf_write_offset      += INIT_AUTH_LEN;

    /* short-term symmetric Nonce for encrypting/decrypting with ChaCha20 */
    memcpy( temp_handshake_buf + tempbuf_write_offset
        ,X_s.bits + shared_secret_read_offset
        ,SHORT_NONCE_LEN
       );

    /* Ready to start constructing the reply buffer to the server. */

    memcpy(*msg_01_buf, &packet_id01, SMALL_FIELD_LEN);


    /*  Client uses KAB_s as key and 12-byte N_s as Nonce in ChaCha20 to
     *  encrypt its long-term public key A, producing the key A_x.
     *
     *  Sends that encrypted long-term public key to the Rosetta server.
     */
    handshake_buf_nonce_offset =
                (3 * sizeof(bigint)) + (2 * SESSION_KEY_LEN) + INIT_AUTH_LEN;

    handshake_buf_key_offset = 3 * sizeof(bigint);

    /* Passed parameters to this call to ChaCha20:
     *
     *  1. INPUT TEXT   : Client's long-term public key unencrypted
     *  2. TEXT_length  : in bytes
     *  3. ChaCha Nonce : inside the locked global handshake memory region.
     *  4. Nonce_length : in uint32_t's
     *  5. ChaCha Key   : inside the locked global handshake memory region
     *  6. Key_length   : in uint32_t's.
     *  7. Destination  : Pointer to correct offset into the reply buffer.
     */
    chacha20( own_pubkey.bits
             ,PUBKEY_LEN
             ,(u32*)(temp_handshake_buf + handshake_buf_nonce_offset)
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32))
             ,(u32*)(temp_handshake_buf + handshake_buf_key_offset)
             ,(u32)(SESSION_KEY_LEN / sizeof(u32))
             ,(*msg_01_buf) + SMALL_FIELD_LEN
            );

    /* Increment the Nonce to not reuse it when decrypting our user index.  */
    /* It's not a BigInt in there but just increment to leftmost 64 bits.   */
    /* And it should have the same effect unless we lucked out with all 1s. */
    /* But generating 64 1s in a row with no 0s should be extremely rare.   */

    aux_ptr64_tempbuf = (u64*)(temp_handshake_buf + handshake_buf_nonce_offset);

    *aux_ptr64_tempbuf += 1;

    /* Only thing left to construct is the HMAC authenticator now. */
    memset(opad, 0x5c, B);
    memset(ipad, 0x36, B);

    /*  Use what's already in the locked memory region to compute HMAC and
     *  to decrypt the user's long-term public key
     *
     *  Server uses KAB_s to compute the same HMAC on A_x (client's long-term
     *  public key in encrypted form) as the client did.
     *
     *  HMAC parameters here:
     *
     *  B    = input block size in bytes of BLAKE2B = 64
     *  H    = hash function to be used - unkeyed BLAKE2B
     *  ipad = buffer of the 0x36 byte repeated B=64 times
     *  K    = key KAB_s
     *  K_0  = K after pre-processing to form a B=64-byte key.
     *  L    = output block size in bytes of BLAKE2B = 64
     *  opad = buffer of the 0x5c byte repeated B=64 times
     *  text = A_x
     */

    /* Step 3 of HMAC construction: HMAC key (KAB) 0-extended to B bytes. */
    memcpy( K0
           ,temp_handshake_buf + (3 * sizeof(bigint))
           ,SESSION_KEY_LEN
          );

    /* Step 4 of HMAC construction */
    for(u64 i = 0; i < B; ++i){
        K0_XOR_ipad[i] = (K0[i] ^ ipad[i]);
    }

    /* step 5 of HMAC construction */
    memcpy(K0_XOR_ipad_TEXT, K0_XOR_ipad, B);
    memcpy(K0_XOR_ipad_TEXT + B, (*msg_01_buf) + SMALL_FIELD_LEN, PUBKEY_LEN);

    /* step 6 of HMAC construction: Call BLAKE2B on K0_XOR_ipad_TEXT */
    blake2b_init(K0_XOR_ipad_TEXT, B + PUBKEY_LEN, 0, L, BLAKE2B_output);

    /* Step 7 of HMAC construction */
    for(u64 i = 0; i < B; ++i){
        K0_XOR_opad[i] = (K0[i] ^ opad[i]);
    }

    /* Step 8 of HMAC: Combine 1st BLAKE2B output with K0_XOR_opad. */
    memcpy(last_BLAKE2B_input + 0, K0_XOR_opad,    B);
    memcpy(last_BLAKE2B_input + B, BLAKE2B_output, L);

    /* Step 9 of HMAC: Call BLAKE2B on the combined buffer. */
    blake2b_init(last_BLAKE2B_input, B + L, 0, L, BLAKE2B_output);

    /* Take the HMAC_TRUNC_BYTES leftmost bytes to form the HMAC output. */

    memcpy((*msg_01_buf) + HMAC_reply_offset, BLAKE2B_output, HMAC_TRUNC_BYTES);

    /* The buffer for the reply to the server is now fully constructed! */

label_cleanup:

    bigint_cleanup(&X_s);
    bigint_cleanup(&zero);
    bigint_cleanup(&B_sM);

    return status;
}

/* This function is one of two possible ones to be called after the recv()
 * in the main processor blocks, expecting an answer after our 2nd login packet.
 *
 * This one is when the Login handshake was successful, there was room in
 * Rosetta for the client, and the server has sent us our user index.
 *
 * Authenticate it, process its contents and alert the user's GUI that login
 * went OK, so it can show it to the user and show the buttons to join or create
 * a chatroom.
 */

/*

    Server ----> Client

================================================================================
| packet ID 01 |  user_ix  |                    SIGNATURE                      |
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/

u8 process_msg_01(u8* msg){

    u64 nonce_offset;
    u64 key_offset;

    bigint* temp_ptr;

    u8 status = 0;

    /* Validate the incoming signature with the server's long-term public key
     * on packet_ID_01 (for now... later it will be of the whole payload). TODO
     */

    status = authenticate_server(msg, SMALL_FIELD_LEN, (2 * SMALL_FIELD_LEN));

    if(status == 1){
        printf("[ERR] Client: Invalid signature in process_msg_01. Drop.\n");
        printf("              Tell GUI to tell user login went badly.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Signature is valid! Can locate our index, decrypt it and save it. */

    nonce_offset = (3 * sizeof(bigint)) + (2 * SESSION_KEY_LEN) + INIT_AUTH_LEN;

    key_offset = (3 * sizeof(bigint)) + (1 * SESSION_KEY_LEN);

    chacha20( msg + SMALL_FIELD_LEN                    /* text - encrypted ix */
             ,SMALL_FIELD_LEN                          /* text_len in bytes   */
             ,(u32*)(temp_handshake_buf + nonce_offset)/* Nonce ptr           */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32))     /* nonceLen in uint32s */
             ,(u32*)(temp_handshake_buf + key_offset)  /* chacha Key - KBA_s  */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32))     /* Key_len in uint32s  */
             ,(u8*)(&own_ix)                           /* output buffer ptr   */
            );

    printf("[OK]  Client: Server told us Login was successful!\n");
    printf("              Tell GUI to tell user the good news!\n\n");
    printf("[OK]  Client: Server told us our user index is: %lu\n\n", own_ix);

label_cleanup:

    //release_handshake_memory_region();

    temp_ptr = (bigint*)temp_handshake_buf;
    bigint_cleanup(temp_ptr);

    temp_ptr = (bigint*)(temp_handshake_buf + sizeof(bigint));
    bigint_cleanup(temp_ptr);

    /* If we WEREN'T told to try login later right after msg_00, but rather
     * after msg_01, which means rosetta is full right now, then the client
     * software will have placed a third bigint object in the memory region
     * at the very least - free its bit buffer too before zeroing it out.
     */
    if(handshake_memory_region_state == 2){
        temp_ptr = (bigint*)(temp_handshake_buf + (2 * sizeof(bigint)));
        bigint_cleanup(temp_ptr);
    }

    memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);

    temp_handshake_memory_region_isLocked = 0;
    handshake_memory_region_state = 0;

    printf("[OK]  Client: Handshake memory region has been released!\n\n");

    return status;

}

/* This function is one of two possible ones to be called after the listen()
 * in the main processor blocks, expecting an answer after our 2nd login packet.
 *
 * This one is when the server told us to try again later. Verify the signature,
 * make sure the reply was really sent by the Rosetta server and that it wasn't
 * modified by a man in the middle attack somewhere along the way.
 *
 * If it's valid, tell the user's GUI that there is no room in Rosetta right now
 * and to try logging in later, so it can display that to the user.
 */

/*
    Server ----> Client

================================================================================
| packet ID 02 |                         SIGNATURE                             |
|==============|===============================================================|
|  SMALL_LEN   |                          SIG_LEN                              |
--------------------------------------------------------------------------------

*/
u8 process_msg_02(u8* msg){

    u8 status = 0;

    /* Validate the incoming signature with the server's long-term public key
     * on packet_ID_02.
     */

    status = authenticate_server(msg, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status == 1){
        printf("[ERR] Client: Invalid signature in process_msg_02. Drop.\n\n");
        goto label_cleanup;
    }

    //release_handshake_memory_region();
    bigint* temp_ptr;

    temp_ptr = (bigint*)temp_handshake_buf;
    bigint_cleanup(temp_ptr);

    temp_ptr = (bigint*)(temp_handshake_buf + sizeof(bigint));
    bigint_cleanup(temp_ptr);

    /* If we WEREN'T told to try login later right after msg_00, but rather
     * after msg_01, which means rosetta is full right now, then the client
     * software will have placed a third bigint object in the memory region
     * at the very least - free its bit buffer too before zeroing it out.
     */
    if(handshake_memory_region_state == 2){
        temp_ptr = (bigint*)(temp_handshake_buf + (2 * sizeof(bigint)));
        bigint_cleanup(temp_ptr);
    }

    memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);

    temp_handshake_memory_region_isLocked = 0;
    handshake_memory_region_state = 0;

label_cleanup:

    return status;
}

/* The user has requested to create a new chatroom.

                                          ENCRYPTED
                            /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
================================================================================
| packet ID 10 |  user_ix  | Decryption Key   | Room_ID+user_ID |  Signature   |
|==============|===========|==================|=================|==============|
|  SMALL_LEN   | SMALL_LEN | ONE_TIME_KEY_LEN |  2 * SMALL_LEN  | SIGNATURE_LEN|
--------------------------------------------------------------------------------

*/
u8 construct_msg_10( unsigned char* requested_userid
                    ,unsigned char* requested_roomid
		    ,uint8_t**      msg_buf
		    ,uint64_t*      msg_len
		    )
{
    bigint one;
    bigint aux1;

    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;

    u64 packet_id10 = PACKET_ID_10;

    FILE* ran_file = NULL;

    u8 status = 0;
    u8 send_K[ONE_TIME_KEY_LEN];
    u8 roomID_userID[2 * SMALL_FIELD_LEN];

    *msg_len = signed_len + SIGNATURE_LEN;
    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    memset(send_K,        0, ONE_TIME_KEY_LEN);
    memset(roomID_userID, 0, 2 * SMALL_FIELD_LEN);

    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    /* Draw a random one-time use 32-byte key K - the Decryption Key. Encrypt it
     * with a different key - the session key KAB from the pair of bidirectional
     * keys in the shared secret with the Rosetta server.
     *
     * Then use Decryption Key K to encrypt the actual part of this packet's
     * payload that needs to be secured and hidden while in transit to the
     * Rosetta server - the Room_ID and User_ID the user picked for that room.
     *
     * The cryptographic signature is to be calculated on the entire payload of
     * the packet - packetID_10, user_ix, key_K, room_ID + user_ID. The Rosetta
     * server already expects a signature of the whole payload.
     */

    ran_file = fopen("/dev/urandom", "r");

    if(!ran_file){
        printf("[ERR] Client: Couldn't open urandom. Abort msg_10 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_10 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Increment nonce as many times as the saved counter says. */
    /*
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&server_nonce_bigint, &one, &aux1);
        bigint_equate2(&server_nonce_bigint, &aux1);
    }
    */

    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */

    chacha20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,(*msg_buf) + (2 * SMALL_FIELD_LEN)   /* output target buffer    */
            );

    /* Maintain nonce's symmetry on both server and client with counters. */
    //++server_nonce_counter;

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    /* Prepare the buffer containing the user_ID and room_ID for encryption. */
    memcpy(roomID_userID, requested_roomid, SMALL_FIELD_LEN);
    memcpy(roomID_userID + SMALL_FIELD_LEN, requested_userid, SMALL_FIELD_LEN);

    strncpy((char*)own_user_id, (char*)requested_userid, SMALL_FIELD_LEN);

    /* Encrypt the user's requested user_ID and room_ID for their new room. */

    chacha20( roomID_userID                        /* text: one-time key K    */
             ,(2 * SMALL_FIELD_LEN)                /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(send_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,(*msg_buf) + sendbuf_roomID_offset   /* output target buffer    */
            );

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    //++server_nonce_counter;

    /* Construct the first 2 parts of this packet - identifier and user_ix. */

    memcpy(*msg_buf, &packet_id10, SMALL_FIELD_LEN);

    memcpy((*msg_buf) + SMALL_FIELD_LEN, &own_ix, SMALL_FIELD_LEN);

    /* Now calculate a cryptographic signature of the whole packet's payload. */

    signature_generate( M, Q, Gm, *msg_buf, signed_len
                       ,((*msg_buf) + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );
label_cleanup:

    if(ran_file){
        fclose(ran_file);
    }

    bigint_cleanup(&one);
    bigint_cleanup(&aux1);

    return status;
}

/* Server told us there is no space currently in Rosetta for new chatrooms.

================================================================================
|  packet ID 11   |                    Cryptographic Signature                 |
|=================|============================================================|
| SMALL_FIELD_LEN |                     SIGNATURE_LEN                          |
--------------------------------------------------------------------------------

*/
u8 process_msg_11(u8* msg){

    u8 status;

    /* All this has to do is validate the signature in the server's packet and
     * if valid, tell GUI to tell the user there's no room in Rosetta currently,
     * if invalid, tell GUI to tell user that something went wrong, try again.
     */

    status = authenticate_server(msg, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_11. Drop.\n");
        printf("              Telling GUI to tell user something's wrong.\n\n");
    }

    else{
        printf("[OK]  Client: Server said there's no space for new rooms.\n");
        printf("              Telling GUI to tell the user about that.\n\n");
    }

    return status;
}

/* Server told us that we created our new chatroom successfully!

================================================================================
|  packet ID 10   |                    Cryptographic Signature                 |
|=================|============================================================|
| SMALL_FIELD_LEN |                     SIGNATURE_LEN                          |
--------------------------------------------------------------------------------

*/
u8 process_msg_10(u8* msg){

    u8 status;

    /* All this has to do is validate the signature in the server's packet and
     * if valid, tell GUI to tell user they successfully created their new room,
     * if invalid, tell GUI to tell user that something went wrong, try again.
     */

    status = authenticate_server(msg, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_10. Drop.\n");
        printf("              Telling GUI to tell user something's wrong.\n\n");
    }

    else{
        printf("[OK]  Client: Server said new chatroom creation went okay.\n");
        printf("              Telling GUI to tell the user the good news.\n\n");
    }

    num_roommates = 0;

    return status;
}

/* Construct the packet that tells the server the user wants to join a chatroom.

                                          ENCRYPTED
                            /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
================================================================================
| packet ID 20 |  user_ix  | Decryption Key   | Room_ID+user_ID |  Signature   |
|==============|===========|==================|=================|==============|
|  SMALL_LEN   | SMALL_LEN | ONE_TIME_KEY_LEN |  2 * SMALL_LEN  | SIGNATURE_LEN|
--------------------------------------------------------------------------------

*/

u8 construct_msg_20( unsigned char* requested_userid
                    ,unsigned char* requested_roomid
                    ,uint8_t**      msg_buf
		    ,uint64_t*      msg_len
		   )
{
    bigint one;
    bigint aux1;

    /* DEBUG */

    u64 room_id_debug;
    memcpy(&room_id_debug, requested_roomid, SMALL_FIELD_LEN);

    /* DEBUG */

    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;

    u64 packet_id20 = PACKET_ID_20;

    *msg_len = signed_len + SIGNATURE_LEN;

    FILE* ran_file = NULL;

    u8 status = 0;
    u8 send_K[ONE_TIME_KEY_LEN];

    u8 roomID_userID[2 * SMALL_FIELD_LEN];

    memset(send_K,        0, ONE_TIME_KEY_LEN);
    memset(roomID_userID, 0, 2 * SMALL_FIELD_LEN);

    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    /* Draw a random one-time use 32-byte key K - the Decryption Key. Encrypt it
     * with a different key - the session key KAB from the pair of bidirectional
     * keys in the shared secret with the Rosetta server.
     *
     * Then use Decryption Key K to encrypt the actual part of this packet's
     * payload that needs to be secured and hidden while in transit to the
     * Rosetta server - the Room_ID and User_ID the user picked for that room.
     *
     * The cryptographic signature is to be calculated on the entire payload of
     * the packet - packetID_20, user_ix, key_K, room_ID + user_ID. The Rosetta
     * server already expects or should expect a signature of the whole payload.
     */

    ran_file = fopen("/dev/urandom", "r");

    if(!ran_file){
        printf("[ERR] Client: Couldn't open urandom. Abort msg_20 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_20 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Increment nonce as many times as the saved counter says. */
    /*
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&server_nonce_bigint, &one, &aux1);
        bigint_equate2(&server_nonce_bigint, &aux1);
    }
    */

    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */

    chacha20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,(*msg_buf) + (2 * SMALL_FIELD_LEN)   /* output target buffer    */
            );

    /* Maintain nonce's symmetry on both server and client with counters. */
    //++server_nonce_counter;

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    /* Prepare the buffer containing the user_ID and room_ID for encryption. */
    memcpy(roomID_userID, requested_roomid, SMALL_FIELD_LEN);
    memcpy(roomID_userID + SMALL_FIELD_LEN, requested_userid, SMALL_FIELD_LEN);

    strncpy((char*)own_user_id, (char*)requested_userid, SMALL_FIELD_LEN);

    /* Encrypt the user's requested user_ID and room_ID for the joining room. */

    chacha20( roomID_userID                        /* text: one-time key K    */
             ,(2 * SMALL_FIELD_LEN)                /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(send_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,(*msg_buf) + sendbuf_roomID_offset   /* output target buffer    */
            );

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    //++server_nonce_counter;

    /* Construct the first 2 parts of this packet - identifier and user_ix. */


    memcpy(*msg_buf, &packet_id20, SMALL_FIELD_LEN);
    memcpy((*msg_buf) + SMALL_FIELD_LEN, &own_ix, SMALL_FIELD_LEN);

    /* Now calculate a cryptographic signature of the whole packet's payload. */

    signature_generate( M, Q, Gm, *msg_buf, signed_len
                       ,((*msg_buf) + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

label_cleanup:

    if(ran_file){
        fclose(ran_file);
    }

    bigint_cleanup(&one);
    bigint_cleanup(&aux1);

    return status;
}

/* The Rosetta server responded to our request to join an existing chatroom and
   sent us the userIDs and public keys of all current chatroom guests, so that
   we can talk to them in a secure and authenticated fashion.

    Server ---> Client

    Main packet structure:

================================================================================
| packetID 20 |        KC        |     N     | Associated Data |   Signature   |
|=============|==================|===========|=================|===============|
|  SMALL_LEN  | ONE_TIME_KEY_LEN | SMALL_LEN |      L bytes    | SIGNATURE_LEN |
--------------------------------------------------------------------------------

    where Associated Data of length L bytes:

================================================================================
| user_id1  | long-term_public_key1 | ... | user_idN  | long-term_public_keyN  |
|===========|=======================|=====|===========|========================|
| SMALL_LEN |      PUBKEY_LEN       | ... | SMALL_LEN |      PUBKEY_LEN        |
--------------------------------------------------------------------------------

    L = N * (SMALL_FIELD_LEN + PUBKEY_LEN).
*/
u8 process_msg_20(u8* msg, u64 msg_len){

    bigint one;
    bigint aux1;
    bigint temp_shared_secret;

    /* Makes for better readability in guest descriptor initializing code. */
    bigint* this_pubkey;

    u8  status = 0;
    u8  recv_K[ONE_TIME_KEY_LEN];
    u8* buf_decrypted_AD = NULL;

    u64* aux_ptr64_msg = (u64*)(msg + SMALL_FIELD_LEN + ONE_TIME_KEY_LEN);

    u64 num_current_guests = *aux_ptr64_msg;

    u64 guest_info_slot_siz = (SMALL_FIELD_LEN + PUBKEY_LEN);
    u64 recv_type20_AD_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 recv_type20_AD_len;
    u64 recv_type20_AD_len_expected;
    u64 recv_type20_signed_len;

    memset(recv_K, 0, ONE_TIME_KEY_LEN);

    bigint_create_from_u32(&temp_shared_secret, MAX_BIGINT_SIZ, 0);
    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    /* First validate the signature the server sent us to authenaticate it. */

    /* Make sure the field that tells us AD's number of present guests is itself
     * containing the correct count value, using the fact that we already know
     * the size of that field and all other fields, except the size of the field
     * that this field is telling us the size of (Associated Data field), and
     * we know how many bytes in total we already read.
     */
    recv_type20_AD_len_expected =
        msg_len - ((2 * SMALL_FIELD_LEN) + SIGNATURE_LEN + ONE_TIME_KEY_LEN);

    recv_type20_AD_len = num_current_guests * guest_info_slot_siz;

    if(recv_type20_AD_len != recv_type20_AD_len_expected){
        printf("[ERR] Client: Invalid field for N in process_msg_20. Drop.\n");
        printf("              Tell GUI to tell user to try join again.\n\n");
        status = 1;
        goto label_cleanup;
    }

    buf_decrypted_AD = (u8*)calloc(1, recv_type20_AD_len);

    recv_type20_signed_len = (2 * SMALL_FIELD_LEN)
                              + ONE_TIME_KEY_LEN
                              + recv_type20_AD_len;

    /* Change this interface to take the 2nd parameter only once, and not have
     * a 3rd parameter (same with 3rd and 4th params in server's version?) since
     * in the final version and in the actual security scheme, ALL packets will
     * always have a signature as the very last thing, of EVERYTHING before it.
     * TODO.
     */
    status =
       authenticate_server(msg, recv_type20_signed_len, recv_type20_signed_len);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_20. Drop.\n");
        printf("              Tell GUI to tell user to try join again.\n\n");
        goto label_cleanup;
    }

    /* Next, use shared secret with server to decrypt KC with KBA chacha key. */
    /* This yields us the key to in turn decrypt the Associated Data with.    */

    /* Increment nonce as many times as the saved counter with server says. */
    /*
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&server_nonce_bigint, &one, &aux1);
        bigint_equate2(&server_nonce_bigint, &aux1);
    }
    */

    chacha20( (msg + SMALL_FIELD_LEN)              /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KBA)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output target buffer    */
            );

    //++server_nonce_counter;

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    /* Now use the obtained one-time key K to decrypt the room guests' info. */

    chacha20( (msg + recv_type20_AD_offset)        /* text: one-time key K    */
             ,recv_type20_AD_len                   /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* Nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,buf_decrypted_AD                     /* output target buffer    */
            );

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    //++server_nonce_counter;

    /* Now initialize the global state for keeping information about guests in
     * the chatroom we're currently in and process this message's associated
     * data, filling out a guest descriptor structure for each guest in it.
     */
    memset(roommates, 0, roommates_arr_siz * sizeof(struct roommate));
    next_free_roommate_slot = 0;
    roommate_slots_bitmask = 0;
    num_roommates = num_current_guests;

    for(u64 i = 0; i < num_current_guests; ++i){

        /* Reflect the new guest slot in the global guest slots bitmask. */
        roommate_slots_bitmask |= BITMASK_BIT_ON_AT(next_free_roommate_slot);

        /* Pointer arithmetic to get to the right guest slot in message's AD. */
        /* No need to dereference the obtained pointer, we're using memcpy(). */

        /* Beginning of THIS SLOT in AD: guest's user_ID. */
        memcpy( roommates[i].guest_user_id
               ,buf_decrypted_AD + (i * guest_info_slot_siz)
               ,SMALL_FIELD_LEN
              );

        /* SMALL_FIELD_LEN bytes offset into THIS SLOT in AD: guest's PubKey. */
        this_pubkey = &(roommates[i].guest_pubkey);

        this_pubkey->bits =(u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/8)));

        memcpy( this_pubkey->bits
               ,buf_decrypted_AD + (i * guest_info_slot_siz) + SMALL_FIELD_LEN
               ,PUBKEY_LEN
              );

        /* Now initialize the rest of this guest's descriptor structure. */
        this_pubkey->size_bits = MAX_BIGINT_SIZ;
        this_pubkey->used_bits = get_used_bits(this_pubkey->bits, PUBKEY_LEN);

        bigint_create_from_u32(&(roommates[i].guest_pubkey_mont), MAX_BIGINT_SIZ, 0);
        get_mont_form(this_pubkey, &(roommates[i].guest_pubkey_mont), M);

        roommates[i].guest_nonce_counter = 0;

        bigint_nullify(&temp_shared_secret);

        /* Now compute a shared secret with the i-th guest to get our pair of
         * bidirectional session keys KAB, KBA and the symmetric ChaCha nonce.
         */
        mont_pow_mod_m(
            &(roommates[i].guest_pubkey_mont)
           ,&own_privkey
           ,M
           ,&temp_shared_secret
        );

        roommates[i].guest_KBA   = (u8*)calloc(1, SESSION_KEY_LEN);
        roommates[i].guest_KAB   = (u8*)calloc(1, SESSION_KEY_LEN);
        roommates[i].guest_Nonce = (u8*)calloc(1, LONG_NONCE_LEN);

        /* Now extract guest_KBA, guest_KAB and guest's symmetric Nonce. */
        memcpy(roommates[i].guest_KBA, temp_shared_secret.bits,SESSION_KEY_LEN);

        memcpy(
            roommates[i].guest_KAB
           ,temp_shared_secret.bits + SESSION_KEY_LEN
           ,SESSION_KEY_LEN
        );

        memcpy(
            roommates[i].guest_Nonce
           ,temp_shared_secret.bits + (2 * SESSION_KEY_LEN)
           ,LONG_NONCE_LEN
        );

        /* This client just joined a room, so its scheme for finding next free
         * guest slot is simple - just increment it, as here we are only
         * processing the initial populating of current guests before us.
         */
        ++next_free_roommate_slot;

    }

label_cleanup:

    bigint_cleanup(&one);
    bigint_cleanup(&aux1);
    bigint_cleanup(&temp_shared_secret);

    free(buf_decrypted_AD);

    return status;
}

/* The Rosetta server replied to our polling request with the information that
   a new room guest has just joined the chatroom we're currently in. Find a spot
   for them in our room's global guests bitmask, fill out a guest descriptor
   structure at this same index in the global guest structs array, initializing
   the required cryptographic artifacts with the new guest for the chat session.

    Server ----> Client

                <---ENCRYPTED---> <-----------ENCRYPTED----------->
================================================================================
| packet ID 21 |        KC       | new_guest_ID | new_guest_PubKey | Signature |
|==============|=================|==============|==================|===========|
|  SMALL_LEN   | ONETIME_KEY_LEN |  SMALL_LEN   |    PUBKEY_LEN    |  SIG_LEN  |
--------------------------------------------------------------------------------

*/
void process_msg_21(u8* msg){

    u64 signed_len;
    u64 new_guest_info_offset = ONE_TIME_KEY_LEN + SMALL_FIELD_LEN;
    u64 guest_ix;
    const u64 new_guest_info_len = SMALL_FIELD_LEN + PUBKEY_LEN;

    bigint  one;
    bigint  aux1;
    bigint  temp_shared_secret;
    bigint* this_pubkey;

    u8 status = 0;
    u8 recv_K[ONE_TIME_KEY_LEN];
    u8 buf_decrypted_guest_info[new_guest_info_len];

    memset(recv_K, 0, ONE_TIME_KEY_LEN);
    memset(buf_decrypted_guest_info, 0, new_guest_info_len);

    bigint_create_from_u32(&temp_shared_secret, MAX_BIGINT_SIZ, 0);
    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    /* First, verify the Schnorr signature in the packet, in order to validate
     * the authenticity of the message, ensure it was not edited in trasnit and
     * that it really is coming from the Rosetta server.
     */
    signed_len = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + PUBKEY_LEN;

    status = authenticate_server(msg, signed_len, signed_len);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_21. Drop.\n");
        goto label_cleanup;
    }

    /* Next, use shared secret with server to decrypt KC with KBA chacha key. */
    /* This yields us the key to in turn decrypt the new guest info with.    */


    /* Increment nonce as many times as the saved counter with server says. */
    /*
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&server_nonce_bigint, &one, &aux1);
        bigint_equate2(&server_nonce_bigint, &aux1);
    }
    */

    /* DECRYPTING the one time key KC back into K.                            */
    chacha20( (msg + SMALL_FIELD_LEN)              /* text: one-time key KC   */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KBA)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output: chacha key K    */
            );

    //++server_nonce_counter;

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);

    /* Now use the obtained one-time key K to decrypt the room guests' info. */

    /* DECRYPTING new guest's information.                                    */
    chacha20( (msg + new_guest_info_offset)        /* text: one-time key K    */
             ,new_guest_info_len                   /* text_len in bytes       */
             ,(u32*)(server_nonce_bigint.bits)     /* Nonce                   */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* Nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,buf_decrypted_guest_info             /* output target buffer    */
            );

    bigint_add_fast(&server_nonce_bigint, &one, &aux1);
    bigint_equate2(&server_nonce_bigint, &aux1);


    //++server_nonce_counter;

    /* Now initialize the global state for keeping information about guests in
     * the chatroom we're currently in, process new guest's included information
     * and fill out their guest descriptor structure in the global array.
     */

    guest_ix = next_free_roommate_slot;

    /* Reflect the new guest slot in the global guest slots bitmask. */
    roommate_slots_bitmask     |= BITMASK_BIT_ON_AT(guest_ix);
    roommate_key_usage_bitmask |= BITMASK_BIT_ON_AT(guest_ix);

    /* Maintain global state for next free roommate slot in the global bitmask.
     *
     * Guest deletion logic makes sure the next free guest slot in the bitmask
     * is always the leftmost available, so just go to the right now, until
     * we see a bit that's not set.
     */

    /* Grab the decrypted guest userid. */
    memcpy(
        roommates[guest_ix].guest_user_id
       ,buf_decrypted_guest_info
       ,SMALL_FIELD_LEN
    );

    /* Grab the decrypted guest's long-term public key. */
    this_pubkey = &(roommates[guest_ix].guest_pubkey);

    this_pubkey->bits = (u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/8)));

    memcpy(
        this_pubkey->bits
       ,buf_decrypted_guest_info + SMALL_FIELD_LEN
       ,PUBKEY_LEN
    );

    /* Now initialize the rest of the new guest's descriptor structure. */
    this_pubkey->size_bits = MAX_BIGINT_SIZ;
    this_pubkey->used_bits = get_used_bits(this_pubkey->bits, PUBKEY_LEN);

    bigint_create_from_u32(&(roommates[guest_ix].guest_pubkey_mont), MAX_BIGINT_SIZ, 0);
    get_mont_form(this_pubkey, &(roommates[guest_ix].guest_pubkey_mont), M);

    roommates[guest_ix].guest_nonce_counter = 0;

    /* Now compute a shared secret with the new guest to get our pair of
     * bidirectional session keys KAB, KBA and the symmetric ChaCha nonce.
     */
    mont_pow_mod_m(
         &(roommates[guest_ix].guest_pubkey_mont)
        ,&own_privkey
        ,M
        ,&temp_shared_secret
    );

    roommates[guest_ix].guest_KBA   = (u8*)calloc(1, SESSION_KEY_LEN);
    roommates[guest_ix].guest_KAB   = (u8*)calloc(1, SESSION_KEY_LEN);
    roommates[guest_ix].guest_Nonce = (u8*)calloc(1, LONG_NONCE_LEN);

    /* Now extract guest_KBA, guest_KAB and guest's symmetric Nonce. */
    memcpy( roommates[guest_ix].guest_KBA
           ,temp_shared_secret.bits
           ,SESSION_KEY_LEN
          );

    memcpy( roommates[guest_ix].guest_KAB
           ,temp_shared_secret.bits + SESSION_KEY_LEN
           ,SESSION_KEY_LEN
          );

    memcpy(
        roommates[guest_ix].guest_Nonce
        ,temp_shared_secret.bits + (2 * SESSION_KEY_LEN)
        ,LONG_NONCE_LEN
    );

    ++num_roommates;
    ++next_free_roommate_slot;


    while(roommate_slots_bitmask & BITMASK_BIT_ON_AT(next_free_roommate_slot)){
        if(next_free_roommate_slot == MAX_CLIENTS){
            printf("[ERR] Client: Room is full! No next_free_roommate_slot!\n");
            break;
        }
        ++next_free_roommate_slot;
    }

    printf("[OK] Client: Synced with a newly joined room guest!\n");

label_cleanup:

    bigint_cleanup(&one);
    bigint_cleanup(&aux1);
    bigint_cleanup(&temp_shared_secret);

    return;
}

/* Send a text message to everyone in our chatroom. Construct the payload.

 Client ----> Server

 Main packet structure:

================================================================================
| packetID 30 |  user_id  |  TXT_LEN   |    AD   |          Signature1         |
|=============|===========|============|=========|=============================|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN  | L bytes |            SIG_LEN          |
--------------------------------------------------------------------------------

 AD - Associated Data, of length L bytes: From T = 1 to (num_guests - 1):

================================================================================
| guestID_1 | encr_key_1 | encr_msg_1| ... |guestID_T | encr_key_T | encr_msg_T|
|===========|============|===========|=====|==========|============|===========|
| SMALL_LEN |  X bytes   |  TXT_LEN  | ... |SMALL_LEN |  X bytes   |  TXT_LEN  |
--------------------------------------------------------------------------------

 L = (People in our chatroom - 1) * (SMALL_LEN + ONE_TIME_KEY_LEN + TXT_LEN)
 X = ONE_TIME_KEY_LEN

*/
u8 construct_msg_30( unsigned char* text_msg, u64  text_msg_len
		            ,uint8_t**      msg_buf,  u64* msg_len
                   )
{

    u64 L = num_roommates * (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len);
    u64 AD_write_offset = 0;
    u64 signed_len;
    u8* associated_data = (u8*)calloc(1, L);
    u8  send_K[ONE_TIME_KEY_LEN];
    u8  status = 0;

    u32* chacha_key = NULL;

    FILE* ran_file = NULL;

    bigint guest_nonce_bigint;
    bigint one;
    bigint aux1;

    size_t ret_val;

    *msg_len = L + (3 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
    signed_len = *msg_len - SIGNATURE_LEN;
    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    memset(send_K, 0, ONE_TIME_KEY_LEN);

    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    guest_nonce_bigint.bits =
    (u8*)(void*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    /* Construct the first 3 sections of the payload. */

    u64 packet_id30 = PACKET_ID_30;

    memcpy( (*msg_buf) + (0 * SMALL_FIELD_LEN), &packet_id30,  SMALL_FIELD_LEN);
    memcpy( (*msg_buf) + (1 * SMALL_FIELD_LEN), own_user_id,   SMALL_FIELD_LEN);
    memcpy( (*msg_buf) + (2 * SMALL_FIELD_LEN), &text_msg_len, SMALL_FIELD_LEN);

    /* Generate the one-time key K to encrypt the text message with.          */
    /* An encrypted version of key K itself is sent to all receivers.         */
    /* It's encrypted with the pair of symmetric session keys (KAB, KBA)      */
    ran_file = fopen("/dev/urandom", "r");

    if(!ran_file){
        printf("[ERR] Client: Couldn't open urandom in msg 30 constructor.\n");
        printf("              Aborting transmission. Telling GUI system.\n\n");
        status = 1;
        goto label_cleanup;
    }

    ret_val = fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file);

    if(ret_val != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom in msg 30 constructor.\n");
        printf("              Aborting transmission. Telling GUI system.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Construct the Associated Data within the payload. */
    for(u64 i = 0; i < MAX_CLIENTS - 1; ++i){
        if( roommate_slots_bitmask & BITMASK_BIT_ON_AT(i) ){

            /* Place this guest's userid. */
            memcpy(
                associated_data + AD_write_offset
               ,roommates[i].guest_user_id
               ,SMALL_FIELD_LEN
            );

            AD_write_offset += SMALL_FIELD_LEN;

            /* Decide whether to encrypt with session key KAB or with KBA. */
            if( roommate_key_usage_bitmask & BITMASK_BIT_ON_AT(i) ){
                chacha_key = (u32*)(roommates[i].guest_KAB);
            }
            else{
                chacha_key = (u32*)(roommates[i].guest_KBA);
            }

            /* Another instance of a manual BigInt constructor from mem :( */
            /* MAX_BIGINT_SIZ is in bits so divide by 8 to get reserved BYTES */

            memcpy(
                guest_nonce_bigint.bits
               ,roommates[i].guest_Nonce
               ,LONG_NONCE_LEN
            );

            guest_nonce_bigint.used_bits =
                get_used_bits(guest_nonce_bigint.bits, LONG_NONCE_LEN);

            guest_nonce_bigint.size_bits = MAX_BIGINT_SIZ;

            /* Increment nonce as many times as counter says for this guest. */
            for(u64 j = 0; j < roommates[i].guest_nonce_counter; ++j){
                bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
                bigint_equate2(&guest_nonce_bigint, &aux1);
            }

            /* Now encrypt and place the text message with K. */
            chacha20(
                send_K                               /* text - the text msg   */
               ,ONE_TIME_KEY_LEN                     /* text_len in bytes     */
               ,(u32*)(guest_nonce_bigint.bits)      /* Nonce (long)          */
               ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* nonce_len in uint32_ts*/
               ,chacha_key                           /* chacha Key            */
               ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_ts  */
               ,associated_data + AD_write_offset    /* output target buffer  */
            );

            AD_write_offset += ONE_TIME_KEY_LEN;

            /* Keep the Nonce with this guest symmetric. */
            bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
            bigint_equate2(&guest_nonce_bigint, &aux1);
            ++(roommates[i].guest_nonce_counter);

            /* Now encrypt and place the text message with K. */
            chacha20(
                text_msg                             /* text - the text msg   */
               ,text_msg_len                         /* text_len in bytes     */
               ,(u32*)(guest_nonce_bigint.bits)      /* Nonce (short)         */
               ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* nonce_len in uint32_ts*/
               ,(u32*)send_K                         /* chacha Key            */
               ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_ts  */
               ,associated_data + AD_write_offset    /* output target buffer  */
            );

            AD_write_offset += text_msg_len;

            /* Increment our Nonce with this guest again to keep it symmetric */
            ++(roommates[i].guest_nonce_counter);

            memset(
                guest_nonce_bigint.bits
               ,0
               ,((size_t)((double)MAX_BIGINT_SIZ/(double)8))
            );
        }
    }

    /* At the end of the above loop, AD_write_offset is AD length. */

    memcpy((*msg_buf) + (3 * SMALL_FIELD_LEN), associated_data, AD_write_offset);

    /* Now calculate a cryptographic signature of the whole packet's payload. */

    signature_generate( M, Q, Gm, *msg_buf, signed_len
                       ,((*msg_buf) + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

label_cleanup:

    bigint_cleanup(&guest_nonce_bigint);
    bigint_cleanup(&one);
    bigint_cleanup(&aux1);

    free(associated_data);

    if(ran_file != NULL){
        fclose(ran_file);
    }

    return status;
}

/* The Rosetta server replied to our polling request with a guest's text msg.

 Server ---> Client

 Main packet structure:

================================================================================
| packetID 30 | sender_id |  TXT_LEN  |    AD   |     Sign1     |    Sign2     |
|=============|===========|===========|=========|===============|==============|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN | L bytes |    SIG_LEN    |   SIG_LEN    |
--------------------------------------------------------------------------------

 AD - Associated Data, of length L bytes: From T = 1 to (num_guests - 1):

================================================================================
| guestID_1 | encr_key_1 | encr_msg_1| ... |guestID_T | encr_key_T | encr_msg_T|
|===========|============|===========|=====|==========|============|===========|
| SMALL_LEN |  X bytes   |  TXT_LEN  | ... |SMALL_LEN |  X bytes   |  TXT_LEN  |
--------------------------------------------------------------------------------

 L = (People in our chatroom - 1) * (SMALL_LEN + ONE_TIME_KEY_LEN + TXT_LEN)
 X = ONE_TIME_KEY_LEN

*/
void process_msg_30(u8* payload, u8* name_with_msg_string, u64* result_chars){

    /* Order of operations here:
     *  - Read in the text message's length from 3rd small field. Verify it.
     *  - Compute the length of one slot in the associated data.
     *  - Locate the sender in the global guest descriptor table.
     *  - Find the offset of the server's signature, Sign2. Validate it.
     *  - Find the offset of the sender client's signature, Sign1. Validate it.
     *  - Iterate over the associated data's slots to find our own userID.
     *  - Use our key KAB/KBA and symmetric Nonce with sender to decrypt key K.
     *  - Use key K and our symmetric Nonce with sender to decrypt the message.
     *  - Tell the GUI system to display the message from the sender.
     */

    u64* aux_ptr64_payload = (u64*)(payload + (2 * SMALL_FIELD_LEN));
    const u64 text_len = *aux_ptr64_payload;
    u64 AD_slot_len;
    u64 AD_len;
    u64 our_AD_slot = MAX_CLIENTS + 1;
    u64 sign2_offset;
    u64 sign1_offset;
    u64 sender_ix = MAX_CLIENTS + 1;
    u64 s_offset;
    u64 e_offset;

    u32* chacha_key;

    char temp_user_id[SMALL_FIELD_LEN];
    const char* GUI_string_helper = ": ";

    u8* AD_pointer = payload + (3 * SMALL_FIELD_LEN);
    u8* our_K_pointer;
    u8* our_msg_pointer;
    u8* decrypted_msg = (u8*)calloc(1, text_len);
    u8  decrypted_key[ONE_TIME_KEY_LEN];
    u8  status = 0;

    bigint *recv_e = NULL;
    bigint *recv_s = NULL;
    bigint  guest_nonce_bigint;
    bigint  one;
    bigint  aux1;

    bigint_create_from_u32(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create_from_u32(&aux1, MAX_BIGINT_SIZ, 0);

    guest_nonce_bigint.bits = (u8*)calloc(1, MAX_BIGINT_SIZ / 8);

    memset(decrypted_key, 0, ONE_TIME_KEY_LEN);
    memset(temp_user_id,  0, SMALL_FIELD_LEN);

    if(text_len < 1 || text_len > MAX_TXT_LEN) {
        printf("[ERR] Client: Text message by a guest is of invalid length.\n");
        printf("              Obtained message length: %lu\n\n", text_len);
        goto label_cleanup;
    }

    AD_slot_len  = SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_len;
    AD_len       = num_roommates * AD_slot_len;
    sign2_offset = (3 * SMALL_FIELD_LEN) + SIGNATURE_LEN + AD_len;
    sign1_offset = sign2_offset - SIGNATURE_LEN;

    /* Find the index of the guest with this userID. */
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if( roommate_slots_bitmask & BITMASK_BIT_ON_AT(i) ){

            /* if userIDs match. */
            if(strncmp( (char*)(roommates[i].guest_user_id)
                       ,(char*)(payload + SMALL_FIELD_LEN)
                       ,SMALL_FIELD_LEN
                      ) == 0
              )
            {
                sender_ix = i;
                break;
            }
        }
    }

    /* If the sender wasn't found in any global descriptor */
    if(sender_ix == MAX_CLIENTS + 1) {
        printf("[ERR] Client: Couldn't find the message sender. Drop.\n\n");
        goto label_cleanup;
    }

    /* Validate the authenticity of the server AND the sending client. */

    struct timeval tv1, tv2;

    gettimeofday(&tv1, NULL);
    status = authenticate_server(payload, sign2_offset, sign2_offset);
    gettimeofday(&tv2, NULL);

    printf( "CLIENT: process_30: authenticate_server() time diff: SEC %lu  --  MICROS %lu\n"
           ,tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec
	  );

    if(status){
        printf("[ERR] Client: Invalid server signature in process_msg_30.\n\n");
        goto label_cleanup;
    }

    /* Now the sender client's signature. */

    /* Reconstruct the sender's signature as the two BigInts that make it up. */
    s_offset = sign1_offset;
    e_offset = sign1_offset + sizeof(bigint) + PRIVKEY_LEN;

    recv_s = (bigint*)(payload + s_offset);
    recv_e = (bigint*)(payload + e_offset);

    recv_s->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    recv_e->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);

    memcpy( recv_s->bits
           ,payload + (sign1_offset + sizeof(bigint))
           ,PRIVKEY_LEN
    );

    memcpy( recv_e->bits
           ,payload + sign1_offset + (2 * sizeof(bigint)) + PRIVKEY_LEN
           ,PRIVKEY_LEN
    );


    gettimeofday(&tv1, NULL);
    /* Verify the sender's cryptographic signature. */
    status = signature_validate(
                     Gm, &(roommates[sender_ix].guest_pubkey_mont)
                    ,M, Q, recv_s, recv_e
                    ,payload, sign1_offset
    );
    gettimeofday(&tv2, NULL);

    printf( "CLIENT: process_30, client's signature_validate(): sec %lu -- micros %lu\n"
	   ,tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec
          );

    if(status) {
        printf("[ERR] Client: Invalid sender signature in msg_30 Drop.\n\n");
        goto label_cleanup;
    }

    /* Now that the packet seems legit, find our slot in the associated data. */
    for(u64 i = 0; i < num_roommates; ++i){

        memcpy(temp_user_id, AD_pointer + (i * AD_slot_len), SMALL_FIELD_LEN);

        if(strncmp(temp_user_id, (char*)own_user_id, SMALL_FIELD_LEN) == 0){
            our_AD_slot = i;
            break;
        }
    }

    /* If we didn't find our userID in the associated data, drop the message. */
    if(our_AD_slot == (MAX_CLIENTS + 1)) {
        printf("[ERR] Client: Didn't find our message slot in AD. Drop.\n\n");
        goto label_cleanup;
    }

    /* Extract the encrypted key and message from our slot in associated data */

    /* Decide whether to encrypt with session key KAB or with KBA. */
    if( roommate_key_usage_bitmask & BITMASK_BIT_ON_AT(sender_ix) ){
        chacha_key = (u32*)(roommates[sender_ix].guest_KBA);
    }
    else{
        chacha_key = (u32*)(roommates[sender_ix].guest_KAB);
    }

    /* Another instance of a manual BigInt constructor from mem :( */
    /* MAX_BIGINT_SIZ is in bits so divide by 8 to get reserved BYTES */

    memcpy(
        guest_nonce_bigint.bits
        ,roommates[sender_ix].guest_Nonce
        ,LONG_NONCE_LEN
    );

    guest_nonce_bigint.used_bits =
        get_used_bits(guest_nonce_bigint.bits, LONG_NONCE_LEN);

    guest_nonce_bigint.size_bits = MAX_BIGINT_SIZ;

    /* Increment nonce as many times as counter says for this guest. */
    for(u64 j = 0; j < roommates[sender_ix].guest_nonce_counter; ++j){
        bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
        bigint_equate2(&guest_nonce_bigint, &aux1);
    }

    our_K_pointer = AD_pointer + (our_AD_slot * AD_slot_len) + SMALL_FIELD_LEN;
    our_msg_pointer = our_K_pointer + ONE_TIME_KEY_LEN;

    /* Place this guest's encrypted one-time ChaCha key. */
    chacha20(
        our_K_pointer                        /* text - recv (encr) K   */
       ,ONE_TIME_KEY_LEN                     /* text_len in bytes      */
       ,(u32*)(guest_nonce_bigint.bits)      /* Nonce (long)           */
       ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* nonce_len in uint32_ts */
       ,chacha_key                           /* chacha Key             */
       ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_ts   */
       ,decrypted_key                        /* output target buffer   */
    );

    ++roommates[sender_ix].guest_nonce_counter;
    bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
    bigint_equate2(&guest_nonce_bigint, &aux1);

    /* Place this guest's encrypted one-time ChaCha key. */
    chacha20(
        our_msg_pointer                       /* text - recv (encr) MSG */
       ,text_len                              /* text_len in bytes      */
       ,(u32*)(guest_nonce_bigint.bits)       /* Nonce (short), counter */
       ,(u32)(SHORT_NONCE_LEN / sizeof(u32))  /* nonce_len in uint32_ts */
       ,(u32*)decrypted_key                   /* chacha Key             */
       ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32)) /* Key_len in uint32_ts   */
       ,decrypted_msg                         /* output target buffer   */
    );

    ++roommates[sender_ix].guest_nonce_counter;

    /* Displayed name format in GUI is always "xxxxNAME: MSG"            */
    /* Always 8 chars space for username and max_txt_len for msg, 1 row. */

    *result_chars = SMALL_FIELD_LEN + 2 + text_len;

    memset(name_with_msg_string, 0, MESSAGE_LINE_LEN);

    /* Construct the string with name and message to be displayed on the GUI. */

    memset(name_with_msg_string, 0x20, (SMALL_FIELD_LEN - strlen( (const char*)(payload + SMALL_FIELD_LEN) )));

    memcpy(name_with_msg_string + (SMALL_FIELD_LEN - strlen( (const char*)(payload + SMALL_FIELD_LEN) )), payload + SMALL_FIELD_LEN, strlen( (const char*)(payload + SMALL_FIELD_LEN) ));
    memcpy(name_with_msg_string + SMALL_FIELD_LEN, GUI_string_helper, 2);
    memcpy(name_with_msg_string + SMALL_FIELD_LEN + 2, decrypted_msg, text_len);

label_cleanup:

    if(recv_s != NULL)
        bigint_cleanup(recv_s);

    if(recv_e != NULL)
        bigint_cleanup(recv_e);

    bigint_cleanup(&guest_nonce_bigint);
    bigint_cleanup(&one);
    bigint_cleanup(&aux1);

    free(decrypted_msg);

    return;
}

/* Our client is sending a poll request to the Rosetta server to see if there
   is anything new that just happened that we need to be aware of, such as
   one of our chat roommates sending a text message, a new roommate joining
   or one leaving our chatroom, or the owner of the chatroom closing it.

 Client ----> Server

================================================================================
| packet ID 40 |  user_ix  |                    SIGNATURE                      |
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
u8 construct_msg_40(u8** msg_buf, u64* msg_len){

    *msg_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 0;

    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    u64 packet_id40 = PACKET_ID_40;

    memcpy(*msg_buf, &packet_id40, SMALL_FIELD_LEN);
    memcpy((*msg_buf) + SMALL_FIELD_LEN, &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */

    signature_generate(
        M, Q, Gm, *msg_buf, 2 * SMALL_FIELD_LEN,
        (*msg_buf) + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );


label_cleanup:

    /* No function cleanup yet. Keep the label for completeness. */

    return status;
}

/* The Rosetta server replied to our polling request with nothing new for us.

   Server ---> Client

================================================================================
|  packet ID 40   |                  Cryptographic Signature                   |
|=================|============================================================|
| SMALL_FIELD_LEN |                        SIGNATURE_LEN                       |
--------------------------------------------------------------------------------
*/
u8 process_msg_40(u8* payload){

    u8 status;

    /* Verify the server's signature first. */
    status = authenticate_server(payload, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_40. Drop.\n\n");
        goto label_cleanup;
    }

    /* Cleanup. */
label_cleanup:

    /* No function cleanup for now. Keep the label for completeness. */

    return status;
}

/* The Rosetta server replied to our polling request with information that
   a NON-OWNER room guest has left our chatroom. Remove that user from our
   global descriptors, bitmasks and other guest bookkeeping.

   Server ---> Client

================================================================================
|  packet ID 50   |  guest_userID   |         Cryptographic Signature          |
|=================|=================|==========================================|
| SMALL_FIELD_LEN | SMALL_FIELD_LEN |              SIGNATURE_LEN               |
--------------------------------------------------------------------------------
*/
void process_msg_50(u8* payload){

    u64 sender_ix = MAX_CLIENTS + 1;

    u8 status;

    /* Verify the server's signature first. */
    status = authenticate_server
	      (payload, 2 * SMALL_FIELD_LEN, 2 * SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_50. Drop.\n\n");
        goto label_cleanup;
    }

    /* Find the index of the guest with this userID. */
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if( roommate_slots_bitmask & BITMASK_BIT_ON_AT(i) ){

            /* if userID matches the one in payload */
            if(strncmp( roommates[i].guest_user_id
                       ,(char*)(payload + SMALL_FIELD_LEN)
                       ,SMALL_FIELD_LEN
                      ) == 0
              )
            {
                printf("[DEBUG] Client: Non-owner left our room. Their index "
                       "in roommates[] is: %lu\n"
                       ,i
                      );
                sender_ix = i;
                break;
            }
        }
    }

    /* If no guest found with the userID in the payload */
    if(sender_ix == MAX_CLIENTS + 1){
        printf("[ERR] Client: No departed guest found with this userID.\n");
        goto label_cleanup;
    }

    /* Remove the guest found at this index from all global bookkeeping. */

    /* If the current next free slot is AFTER this guest's slot, update the
     * next free slot to be back here, making sure the next free guest slot
     * is always the leftmost unset bit in the global bitmasks and descriptors.
     */
    if(sender_ix < next_free_roommate_slot){
        next_free_roommate_slot = sender_ix;
    }

    /* Make sure we deallocate any heap memory pointed to by pointers contained
     * in the descriptor struct or by pointers in an object which is itself part
     * of the descriptor struct, BEFORE we zero out the descriptor itself.
     *
     * Additionally, use a volatile pointer to the memory buffers containing
     * sensitive information, in combination with a -O0 and noinline marked
     * function to prevent the compiler from optimizing away the memory clearing
     * upon determining that its result is not used anywhere.
     *
     */

    volatile uint8_t* secure_erase_ptr;
    uint64_t n_bytes_to_erase;

    secure_erase_ptr = (volatile u8*)roommates[sender_ix].guest_user_id;
    n_bytes_to_erase = SMALL_FIELD_LEN;
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    secure_erase_ptr = (volatile u8*)roommates[sender_ix].guest_pubkey.bits;
    n_bytes_to_erase = (uint64_t)(MAX_BIGINT_SIZ / 8);
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    secure_erase_ptr =(volatile u8*)roommates[sender_ix].guest_pubkey_mont.bits;
    n_bytes_to_erase = (uint64_t)(MAX_BIGINT_SIZ / 8);
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    bigint_cleanup(&(roommates[sender_ix].guest_pubkey));
    bigint_cleanup(&(roommates[sender_ix].guest_pubkey_mont));

    secure_erase_ptr = (volatile u8*)roommates[sender_ix].guest_KBA;
    n_bytes_to_erase = SESSION_KEY_LEN;
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    secure_erase_ptr = (volatile u8*)roommates[sender_ix].guest_KAB;
    n_bytes_to_erase = SESSION_KEY_LEN;
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    secure_erase_ptr = (volatile u8*)roommates[sender_ix].guest_Nonce;
    n_bytes_to_erase = LONG_NONCE_LEN;
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    free(roommates[sender_ix].guest_KBA);
    free(roommates[sender_ix].guest_KAB);
    free(roommates[sender_ix].guest_Nonce);

    /* Now zero out the descriptor itself without the risk of memory leaks. */
    secure_erase_ptr = (volatile u8*)&(roommates[sender_ix]);
    n_bytes_to_erase = sizeof(struct roommate);
    erase_mem_secure(secure_erase_ptr, n_bytes_to_erase);

    roommate_slots_bitmask     &= ~(BITMASK_BIT_ON_AT(sender_ix));
    roommate_key_usage_bitmask &= ~(BITMASK_BIT_ON_AT(sender_ix));

    --num_roommates;

    /* Cleanup. */
label_cleanup:

    /* No function cleanup for now. Keep the label for completeness. */

    return;
}

/* Tell the Rosetta server that the user wants to leave the chatroom.

 Client ----> Server

================================================================================
| packet ID 50 |  user_ix  |                    SIGNATURE                      |
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
u8 construct_msg_50(uint8_t** msg_buf, uint64_t* msg_len)
{
    u8 status = 0;

    *msg_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    for(u64 i = 0; i < MAX_CLIENTS; ++i){

        /* Make sure we deallocate any memory pointed to by pointers contained
         * in the struct itself or by pointers in an object that's part of the
         * struct BEFORE we zero out the descriptor itself.
         */
        if(roommate_slots_bitmask & BITMASK_BIT_ON_AT(i))
        {
            memset(roommates[i].guest_user_id, 0, SMALL_FIELD_LEN);

            bigint_nullify(&(roommates[i].guest_pubkey));
            bigint_nullify(&(roommates[i].guest_pubkey_mont));

            memset(roommates[i].guest_KBA,   0, SESSION_KEY_LEN);
            memset(roommates[i].guest_KAB,   0, SESSION_KEY_LEN);
            memset(roommates[i].guest_Nonce, 0, LONG_NONCE_LEN );

            bigint_cleanup(&(roommates[i].guest_pubkey));
            bigint_cleanup(&(roommates[i].guest_pubkey_mont));

            free(roommates[i].guest_KBA);
            free(roommates[i].guest_KAB);
            free(roommates[i].guest_Nonce);
        }
    }

    /* Now zero out all global descriptors without the risk of memory leaks. */
    memset(roommates, 0, (roommates_arr_siz * sizeof(struct roommate)));

    /* Reset the two global guest bitmasks and other bookkeeping information. */
    roommate_slots_bitmask     = 0;
    roommate_key_usage_bitmask = 0;
    num_roommates              = 0;
    next_free_roommate_slot    = 0;
    memset(own_user_id, 0, SMALL_FIELD_LEN);

    u64 packet_id50 = PACKET_ID_50;

    memcpy(*msg_buf, &packet_id50, SMALL_FIELD_LEN);

    memcpy(((*msg_buf) + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    signature_generate(
        M, Q, Gm, *msg_buf, 2 * SMALL_FIELD_LEN,
        (*msg_buf) + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

label_cleanup:

    /* No function cleanup yet. Keep the label for completeness. */

    return status;
}

/* The Rosetta server replied to our polling request with information that
   the chatroom owner has left our chatroom. Delete the entire room and reset
   all global bookkeeping.

   Server ---> Client

================================================================================
|  packet ID 51   |                  Cryptographic Signature                   |
|=================|============================================================|
| SMALL_FIELD_LEN |                        SIGNATURE_LEN                       |
--------------------------------------------------------------------------------
*/
void process_msg_51(u8* payload){

    u8 status = 0;

    /* Verify the server's signature first. */
    status = authenticate_server(payload, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_51. Drop.\n\n");
        goto label_cleanup;
    }

    for(u64 i = 0; i < MAX_CLIENTS; ++i){

        /* Make sure we deallocate any memory pointed to by pointers contained
         * in the struct itself or by pointers in an object that's part of the
         * struct BEFORE we zero out the descriptor itself.
         */
        if(roommate_slots_bitmask & BITMASK_BIT_ON_AT(i))
        {
            memset(roommates[i].guest_user_id, 0, SMALL_FIELD_LEN);

            bigint_nullify(&(roommates[i].guest_pubkey));
            bigint_nullify(&(roommates[i].guest_pubkey_mont));

            memset(roommates[i].guest_KBA,   0, SESSION_KEY_LEN);
            memset(roommates[i].guest_KAB,   0, SESSION_KEY_LEN);
            memset(roommates[i].guest_Nonce, 0, LONG_NONCE_LEN );

            bigint_cleanup(&(roommates[i].guest_pubkey));
            bigint_cleanup(&(roommates[i].guest_pubkey_mont));

            free(roommates[i].guest_KBA);
            free(roommates[i].guest_KAB);
            free(roommates[i].guest_Nonce);
        }
    }

    /* Now zero out all global descriptors without the risk of memory leaks. */
    memset(roommates, 0, roommates_arr_siz * sizeof(struct roommate));

    /* Reset the two global guest bitmasks and other bookkeeping information. */
    roommate_slots_bitmask     = 0;
    roommate_key_usage_bitmask = 0;
    num_roommates              = 0;
    next_free_roommate_slot    = 0;

    /* Use this to alert the main thread to stop texting, if it happens to not
     * be blocked on the scanf() call for some milliseconds (which this thread
     * unblocks it from by sending it a signal with the following pthread_kill).
     */
    pthread_mutex_lock(&poll_mutex);
    texting_should_stop = 1;
    pthread_mutex_unlock(&poll_mutex);

    /* This DOES NOT kill the main thread, it merely sends it a signal for which
     * the main thread has installed a custom signal handler function. This call
     * is done only to unblock the main thread from its blocked scanf() call.
     * In the desktop GUI version, this signal will be used to alert the GUI
     * to draw an info box that the room the user is in was closed by the owner
     * and retract the GUI elements that allow the user to send text messages.
     */
    printf("\n-->[DEBUG] Client: got MSG_51: sending SIGNAL to main thread!\n");
    pthread_kill(main_thread_id, SIGUSR1);


    /* Cleanup. */
label_cleanup:

    /* No function cleanup for now. Keep the label for completeness. */

    return;
}

/* Tell the Rosetta server that the user wants to log off.

 Client ----> Server

================================================================================
| packet ID 60 |  user_ix  |                    SIGNATURE                      |
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
u8 construct_msg_60(uint8_t** msg_buf, uint64_t* msg_len){

    u8 status = 0;

    *msg_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    *msg_buf = (u8*)(void*)calloc(1, *msg_len);

    u64 packet_id60 = PACKET_ID_60;

    memcpy(*msg_buf, &packet_id60, SMALL_FIELD_LEN);

    memcpy(((*msg_buf) + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    signature_generate(
        M, Q, Gm, *msg_buf, 2 * SMALL_FIELD_LEN,
        (*msg_buf) + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    own_ix = 0;

label_cleanup:

    /* No function cleanup yet. Keep the label for completeness. */

    return status;
}
