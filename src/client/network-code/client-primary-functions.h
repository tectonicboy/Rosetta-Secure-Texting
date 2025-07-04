#include <errno.h>

#include "../../lib/coreutil.h"

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


/* This function pointer determines whether to communicate through Unix Domain
 * sockets or through TCP sockets. A separate function handles these methods of
 * communication. The former is for the Rosetta Testing Framework and the latter
 * is for running the real messaging system.
 *
 * The Rosetta Testing Framework simulates people texting each other by spawning
 * processes within the same operating system and having them talk to the server
 * with interprocess communications over Unix Domain sockets instead of TCP.
 * Everything else, including GUI, remains exactly the same as the real system.
 *
 * The client initialization routine sets this function pointer accordingly
 * depending on which one we are currently running.
 */

uint8_t (*send_payload)(uint8_t*, uint64_t);

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
char own_user_id[SMALL_FIELD_LEN];

u64 server_nonce_counter = 0;

pthread_mutex_t mutex;
pthread_t poller_threadID;

u8 own_privkey_buf[PRIVKEY_LEN];

bigint server_shared_secret;
bigint nonce_bigint;
bigint *M  = NULL;
bigint *Q  = NULL;
bigint *G  = NULL;
bigint *Gm = NULL;
bigint *server_pubkey = NULL;
bigint server_pubkey_mont;
bigint own_privkey;
bigint own_pubkey;

/* These are for talking securely to the Rosetta server only. */
u8 *KAB, *KBA;

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

    /*
    printf("[DEBUG] Client: s and e received by server (before validate):\n\n");

    printf("[DEBUG] Client: received s:\n");
    bigint_print_info(recv_s);
    bigint_print_bits(recv_s);

    printf("[DEBUG] Client: received e:\n");
    bigint_print_info(recv_e);
    bigint_print_bits(recv_e);
    */

    /* Verify the sender's cryptographic signature. */
    status = Signature_VALIDATE(
        Gm, &server_pubkey_mont, M, Q, recv_s, recv_e, signed_ptr, signed_len
    );

    free(recv_s->bits);
    free(recv_e->bits);

    return status;
}


#include "client-packet-functions.h"


/* Do everything that can be done before we construct message_00 to begin
 * the login handshake protocol to securely transport our long-term public key
 * to the server so it can also compute the same DH shared secret that we did,
 * thus establishing a secure and authenticated communication channel with it.
 */
/* Load user's public key. Decrypt and load user's private key. */

/* Load DH constants and server's public key, compute a shared secret. */

/* Initialize client software's internal state and bookkeeping. */

/* Initialize stuff needed for the Unix Sockets API. */

/* Attempt to establish a connection with the Rosetta server. */

/* Initialize polling mutex. */
u8 self_init(u8* password, int password_len){

    const u32 chacha_key_len = 32;
    u32 pw_bytes_for_zeroing = PASSWORD_BUF_SIZ - password_len;

    u8 status = 0;
    u8 saved_nonce[LONG_NONCE_LEN];
    u8 saved_string[ARGON_STRING_LEN];
    u8 saved_privkey[PRIVKEY_LEN];
    u8 saved_pubkey[PUBKEY_LEN];
    u8 b2b_pubkey_output[64];
    u8 Salt[ARGON_STRING_LEN + 64];
    u8 argon2_output_tag[ARGON_HASH_LEN];
    u8 V[chacha_key_len];
    u8 decrypted_privkey_buf[PRIVKEY_LEN];

    FILE* savefile = NULL;

    bigint* calculated_A = NULL;

    struct Argon2_parms prms;

    send_payload = send_to_tcp_server;

    memset(&prms, 0, sizeof(struct Argon2_parms));

    /* Initialize data structures for maintaining global state & bookkeeping. */
    memset(roommates,           0, roommates_arr_siz * sizeof(struct roommate));
    memset(own_privkey_buf,     0, PRIVKEY_LEN);
    memset(temp_handshake_buf,  0, TEMP_BUF_SIZ);

    /* Load user's public key, decrypt and load user's private key. */

    savefile = fopen("../bin/user_save.dat", "r");

    if(savefile == NULL){
        printf("[ERR] Client: couldn't open the user's save file. Aborting.\n");
        status = 1;
	goto label_cleanup;
    }

    /* Read savefile in the same order that Registration writes it in. */

    /* First is Nonce for decrypting the saved private key. */
    if(fread(saved_nonce, 1, LONG_NONCE_LEN, savefile) != LONG_NONCE_LEN){
        printf("[ERR] Client: couldn't get nonce from savefile[0].\n");
        status = 1;
        goto label_cleanup;
    }

    /* Second is the user's long-term private key in encrypted form. */
    if(fread(saved_privkey, 1, PRIVKEY_LEN, savefile) != PRIVKEY_LEN){
        printf("[ERR] Client: couldn't get encr. privkey from savefile[1].\n");
        status = 1;
        goto label_cleanup;
    }

    /* Third is the user's long-term public key non-encrypted. */
    if(fread(saved_pubkey, 1, PUBKEY_LEN, savefile) != PUBKEY_LEN){
        printf("[ERR] Client: couldn't get pubkey from savefile[2].\n");
        status = 1;
        goto label_cleanup;
    }

    /* Fourth and last is the 8-byte string - part of Argon2 parameter S. */
    if(fread(saved_string, 1, ARGON_STRING_LEN, savefile) != ARGON_STRING_LEN){
        printf("[ERR] Client: couldn't get string from savefile[3].\n");
        status = 1;
        goto label_cleanup;
    }

    printf("[DEBUG] Client: Nonce 16 bytes:\n");

    for(u32 i = 0; i < LONG_NONCE_LEN; ++i){
        printf("%03u ", saved_nonce[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("[DEBUG] Client: Encrypted privkey 40 bytes:\n");

    for(u32 i = 0; i < PRIVKEY_LEN; ++i){
        printf("%03u ", saved_privkey[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("[DEBUG] Client: Plaintext pubkey 384 bytes:\n");

    for(u32 i = 0; i < PUBKEY_LEN; ++i){
        printf("%03u ", saved_pubkey[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("[DEBUG] Client: Argon Salt String 8 bytes:\n");

        for(u32 i = 0; i < ARGON_STRING_LEN; ++i){
        printf("%03u ", saved_string[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Now decrypt the saved private key. Call Argon2, then call ChaCha20. */

    /* Fill in the parameters to Argon2. */

    prms.p = 4;                 /* How many threads to use.             */
    prms.T = ARGON_HASH_LEN;    /* How many bytes of output we want.    */
    prms.m = 2097000;           /* How many kibibytes of memory to use. */
    prms.t = 1;                 /* How many passes Argon2 should do.    */
    prms.v = 0x13;              /* Constant in Argon2 spec.             */
    prms.y = 0x02;              /* Constant in Argon2 spec.             */

    /* Zero-extend the password to 16 bytes including a null terminator.   */
    /* Len does not include the null terminator already placed by the GUI. */
    if(pw_bytes_for_zeroing > 0){
        memset(password + password_len, 0, pw_bytes_for_zeroing);
    }

    prms.P = password;

    /* Now construct Argon2 Salt parameter. We already have 1st part here     */
    /* Salt = saved_string || BLAKE2B{64}(client's saved long-term public key)*/

    /* Call Blake2b to get the second part of the Salt parameter. */
    BLAKE2B_INIT(saved_pubkey, PUBKEY_LEN, 0, 64, b2b_pubkey_output);

    /* Now construct the complete Salt parameter with the 2 components. */
    memcpy(Salt, saved_string, ARGON_STRING_LEN);
    memcpy(Salt + ARGON_STRING_LEN, b2b_pubkey_output, 64);

    prms.S = Salt;

    /* Set other parameters to Argon2. */
    prms.len_P = PASSWORD_BUF_SIZ;        /* Length of password (as a key)    */
    prms.len_S = (ARGON_STRING_LEN + 64); /* Length of the Salt parameter     */
    prms.len_K = 0;                       /* unused here, so set length to 0  */
    prms.len_X = 0;                       /* unused here, so set length to 0  */

    printf("[DEBUG] Client: Before calling argon2 in LOGIN, parms:\n");
    printf("sizeof(argon2_parms) = %lu\n\n", sizeof(struct Argon2_parms));

    for(u32 i = 0; i < sizeof(struct Argon2_parms); ++i){
        printf("%03u ", *(((u8*)(&prms)) + i) );
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Password buffer of len %lu:\n", prms.len_P);
    for(u32 i = 0; i < prms.len_P; ++i){
        printf("%03u ", prms.P[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Salt buffer of len %lu:\n", prms.len_S);
    for(u32 i = 0; i < prms.len_S; ++i){
        printf("%03u ", prms.S[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    Argon2_MAIN(&prms, argon2_output_tag);

    /* Let V be the leftmost 32 (chacha_key_len) bytes of Argon2's output hash.
     * Use V as a key in ChaCha20, along with the saved 16-byte Nonce
     * (from user's save file) to decrypt the user's saved private key.
     */
    memcpy(V, argon2_output_tag, chacha_key_len);

    /* Decrypt the saved private key. */
    CHACHA20( saved_privkey                       /* text - private key  */
             ,PRIVKEY_LEN                         /* text_len in bytes   */
             ,(u32*)saved_nonce                   /* Nonce ptr           */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32)) /* nonceLen in uint32s */
             ,(u32*)V                             /* chacha Key ptr      */
             ,(u32)(chacha_key_len / sizeof(u32)) /* Key_len in uint32s  */
             ,decrypted_privkey_buf               /* output buffer ptr   */
            );

    /* Initialize the global BigInts storing user's public and private keys. */
    bigint_create(&own_privkey, MAX_BIGINT_SIZ, 0);
    memcpy(own_privkey.bits, decrypted_privkey_buf, PRIVKEY_LEN);
    own_privkey.used_bits = get_used_bits(decrypted_privkey_buf, PRIVKEY_LEN);
    own_privkey.free_bits = MAX_BIGINT_SIZ - own_privkey.used_bits;

    bigint_create(&own_pubkey, MAX_BIGINT_SIZ, 0);
    memcpy(own_pubkey.bits, saved_pubkey, PUBKEY_LEN);
    own_pubkey.used_bits = get_used_bits(saved_pubkey, PUBKEY_LEN);
    own_pubkey.free_bits = MAX_BIGINT_SIZ - own_pubkey.used_bits;

    printf("[OK] Client: Checking decrypted private key...\n");

    /* Compute a public key with that private key and M, Q, G. If it's the same
     * as the public key stored on the filesystem, the private key was
     * decrypted successfully, with the original correct password.
     */

    save_BIGINT_to_DAT("temp_priv.dat", &own_privkey);

    calculated_A = gen_pub_key(PRIVKEY_LEN, "temp_priv.dat", MAX_BIGINT_SIZ);

    system("rm temp_priv.dat");

    /* Now compare the calculated and the saved public keys. */
    if(bigint_compare2(calculated_A, &own_pubkey) != 2){
        printf("[ERR] Client: Password did NOT lead to correct privkey.\n\n");
        status = 1;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Password unlocked the private key correctly!\n");
    }
    /* Load other BigInts needed for the cryptography to work and be secure. */

    /* Diffie-Hellman modulus M, 3071-bit prime positive integer. */
    M = get_BIGINT_from_DAT(3072, "../bin/saved_M.dat", 3071, MAX_BIGINT_SIZ);

    if(M == NULL){
        printf("[ERR] Client: Failed to get M from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* 320-bit prime exactly dividing M-1, making M cryptographically strong. */
    Q = get_BIGINT_from_DAT(320, "../bin/saved_Q.dat", 320,  MAX_BIGINT_SIZ);

    if(Q == NULL){
        printf("[ERR] Client: Failed to get Q from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Diffie-Hellman generator G = 2^((M-1)/Q) */
    G = get_BIGINT_from_DAT(3072, "../bin/saved_G.dat", 3071, MAX_BIGINT_SIZ);

    if(G == NULL){
        printf("[ERR] Client: Failed to get G from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_BIGINT_from_DAT(3072, "../bin/saved_Gm.dat", 3071, MAX_BIGINT_SIZ);

    if(Gm == NULL){
        printf("[ERR] Client: Failed to get Gm from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Grab the server's public key. */
    server_pubkey =
    get_BIGINT_from_DAT(3072, "../bin/server_pubkey.dat", 3071, MAX_BIGINT_SIZ);

    if(server_pubkey == NULL){
        printf("[ERR] Client: Failed to get server pubkey from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Initialize the shared secret with the server. */
    bigint_create(&server_pubkey_mont,   MAX_BIGINT_SIZ, 0);
    bigint_create(&server_shared_secret, MAX_BIGINT_SIZ, 0);

    Get_Mont_Form(server_pubkey, &server_pubkey_mont, M);

    MONT_POW_modM(&server_pubkey_mont, &own_privkey, M, &server_shared_secret);

    /* Initialize the pair of bidirectional session keys (KBA, KAB) w/ server */

    /*  On client's side:
     *       - KAB = least significant 32 bytes of shared secret
     *       - KBA = next 32 bytes of shared secret
     *       - swap KBA with KAB if A < B  (our and server's public keys)
     */

    /* if A < B */
    if( (bigint_compare2(&own_pubkey, server_pubkey)) == 3){
        KAB = server_shared_secret.bits + SESSION_KEY_LEN;
        KBA = server_shared_secret.bits;
    }
    else{
        KAB = server_shared_secret.bits;
        KBA = server_shared_secret.bits + SESSION_KEY_LEN;
    }

    /* calloc() needs it in bytes, MAX_BIGINT_SIZ is in bits, so divide by 8. */
    nonce_bigint.bits =
    (u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    memcpy( nonce_bigint.bits
           ,server_shared_secret.bits + (2 * SESSION_KEY_LEN)
           ,LONG_NONCE_LEN
          );

    nonce_bigint.used_bits = get_used_bits(nonce_bigint.bits, LONG_NONCE_LEN);
    nonce_bigint.size_bits = MAX_BIGINT_SIZ;
    nonce_bigint.free_bits = MAX_BIGINT_SIZ - nonce_bigint.used_bits;

    /* Initialize the Rosetta server's address structure. */

    memset(&servaddr, 0, sizeof(struct sockaddr_in));

    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDR);
    servaddr.sin_port        = htons(port);

    /* Initialize the mutex that will be used to prevent the main thread and
     * the poller thread from writing/reading the same data in parallel.
     */
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Initialize the socket before the connect() call. */
    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(own_socket_fd == -1) {
        printf("[ERR] Client: socket() failed. Terminating.\n");
        perror("errno:");
        status = 1;
	goto label_cleanup;
    }

    if(
        setsockopt(
           own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval1, sizeof(optval1)
        )
        != 0
    )
    {
        printf("[ERR] Client: set socket option failed.\n\n");
	status = 1;
	goto label_cleanup;
    }

    printf("[OK]  Client: Socket file descriptor obtained!\n");

    /* Connect to the Rosetta server. */

    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        == -1
      )
    {
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        perror("connect() failed, errno: ");
        status = 1;
	goto label_cleanup;
    }

    printf("[OK]  Client: Connect() call finished, won't be re-attempted.\n");


label_cleanup:


    if(savefile){
	    fclose(savefile);
    }

    if(calculated_A != NULL){
        free(calculated_A->bits);
        free(calculated_A);
    }

    return status;
}

void* begin_polling(void* input){

    /* Construct the poll packet only once, and keep sending it. */

    u8  ret;
    u8  text_message_line[MESSAGE_LINE_LEN];
    u8* received_buf = (u8*)calloc(1, MAX_MSG_LEN);

    u64 curr_msg_type = 0;
    u64 pending_messages = 0;
    u64 read_ix = 0;
    u64 block_len;
    u64 obtained_text_message_line_len = 0;
    u64 curr_msg_len;

    int64_t bytes_read;

    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = 200000000; /* 200,000,000 nanoseconds = 0.2 seconds */

    for(;;){

        nanosleep(&ts, NULL);

        printf("[OK] Client: Sending a poll request to the server!\n");

        ret = construct_msg_40();

        if(ret){
            printf("[ERR] Client: Sending of poll packet failed! Read logs!\n");
            goto loop_cleanup;
        }

        /* Wait for server to tell us if there's anything for us unreceived. */
        bytes_read = recv(own_socket_fd, received_buf, MAX_MSG_LEN, 0);

        if( bytes_read == -1
            ||
            bytes_read < (int64_t)(SIGNATURE_LEN + SMALL_FIELD_LEN)
          )
        {
            printf( "[ERR] Client: Failed to receive server's poll reply!\n\n");
            goto loop_cleanup;
        }

        /* Call the appropriate function depending on server's response. */
        if( *((u64*)(received_buf)) == PACKET_ID_40 ){
            printf("[OK] Client: Server said nothing new after polling.\n\n");
            process_msg_40(received_buf);
        }
/*

 One or more pending messages were found for the polling client.
 Send them all at once.

 Server ----> Client

================================================================================
| packetID 41 |     T     |    L_1    | MSG1 |...|    L_T    | MSG_T|  Signat  |
|=============|===========|===========|======|===|===========|======|==========|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN | L_1  |...| SMALL_LEN |  L_T | SIG_LEN  |
--------------------------------------------------------------------------------

*/
        else if ( *((u64*)(received_buf)) == PACKET_ID_41 ) {

            pending_messages = *((u64*)(received_buf + SMALL_FIELD_LEN));

            read_ix = 2 * SMALL_FIELD_LEN;

            /* At end, read_ix = how many bytes a signature was computed on. */
            for(u64 i = 0; i < pending_messages; ++i){
                block_len = *((u64*)(received_buf + read_ix));
                read_ix += block_len + SMALL_FIELD_LEN;
            }

            /* Verify the cryptographic signature now. */
            ret = authenticate_server(received_buf, read_ix, read_ix);

            if(ret == 1){
                printf("[ERR] Client: Bad signature in polling reply.\n\n");
                goto loop_cleanup;
            }

            /* Start at first message contents. */
            read_ix = 3 * SMALL_FIELD_LEN;

            /* Valid pending message types: 50, 51, 21, 30 */

            /* packet_ID and signature are valid - process each pending MSG. */
            for(u64 i = 0; i < pending_messages; ++i){

                curr_msg_type = *((u64*)(received_buf + read_ix));

                curr_msg_len =
                            *((u64*)(received_buf + read_ix - SMALL_FIELD_LEN));

                if(curr_msg_type == PACKET_ID_50){
		    
                    process_msg_50(received_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_51){
                    process_msg_51(received_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_21){
                    process_msg_21(received_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_30){
                    process_msg_30( received_buf + read_ix
                                   ,text_message_line
                                   ,&obtained_text_message_line_len
                                  );

                    /* Tell GUI to display the message with obtained length. */
                    /* TODO */

                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
            }
        }
        else{
            printf("[ERR] Client: Strange reply by server to poll request.\n");
        }

loop_cleanup:

        memset(received_buf, 0, MAX_MSG_LEN);
    }

    return NULL;
}

void start_polling_thread(){

    /* Start the thread function which sends poll packets to the Rosetta server
     * in an infinite loop and processes the several different answer packets.
     */
    if( (pthread_create(&poller_threadID, NULL, &begin_polling, NULL)) != 0){
        printf("[ERR] Client: pthread_create failed for polling function.\n\n");
        exit(1);
    }
}

u8 reg(u8* password, int password_len){

    const u32 chacha_key_len = 32;
    u32 pw_bytes_for_zeroing = PASSWORD_BUF_SIZ - password_len;

    const u64 argon2_len_Salt = ARGON_STRING_LEN + 64;
    u64 save_offset = 0;
    const u64 save_len =
    ARGON_STRING_LEN + PUBKEY_LEN + PRIVKEY_LEN + LONG_NONCE_LEN;

    u8 status = 0;
    u8 privkey_buf          [PRIVKEY_LEN];
    u8 argon2_salt_string   [ARGON_STRING_LEN];
    u8 b2b_pubkey_output    [64];
    u8 Salt                 [argon2_len_Salt];
    u8 argon2_output_tag    [ARGON_HASH_LEN];
    u8 V                    [chacha_key_len];
    u8 chacha_nonce_buf     [LONG_NONCE_LEN];
    u8 encrypted_privkey_buf[PRIVKEY_LEN];
    u8 user_save_buf        [save_len];

    /* Salt = S || BLAKE2B{64}(A) */
    /* S is a random 8 byte string, so Salt length is 64+8 = 72 bytes. */
    /* Access /dev/urandom for random 8-byte string S for Argon2 Salt. */
    FILE* ranfile   = NULL;
    FILE* user_save = NULL;

    struct Argon2_parms prms;

    bigint* A_longterm;
    bigint temp_privkey;

    temp_privkey.bits = (u8*)calloc(1, MAX_BIGINT_SIZ);

    memset(&prms, 0, sizeof(struct Argon2_parms));

    printf("[OK]  TCP_Client obtained user's register password from GUI!\n");
    printf("      password_len = %d\n", password_len);
    printf("      password: %s\n\n", password);

    /* Registration step 1: Generate a long-term private/public keys a/A. */

    /* a = random in the range [1, Q) */
    gen_priv_key(PRIVKEY_LEN, privkey_buf);

    /* Interface generating a pub_key still needs priv_key in a file. TODO.  */
    /* Putting it in a file needs it in the form of bigint object. Make one. */
    memcpy(temp_privkey.bits, privkey_buf, PRIVKEY_LEN);
    temp_privkey.size_bits = MAX_BIGINT_SIZ;
    temp_privkey.used_bits = get_used_bits(privkey_buf, PRIVKEY_LEN);
    temp_privkey.free_bits = MAX_BIGINT_SIZ - temp_privkey.used_bits;

    save_BIGINT_to_DAT("temp_privkey.dat", &temp_privkey);

    /* A = G^a mod M */
    A_longterm = gen_pub_key(PRIVKEY_LEN, "temp_privkey.dat", MAX_BIGINT_SIZ);

    /* Registration step 2: Use the password as a secret key in Argon2 hashing
     *                      algorithm, whose output hash we use as a
     *                      cryptographic key in another hashing algorith,
     *                      ChaCha20, to encrypt the user's private key.
     */

    /* Fill in the parameters to Argon2. */

    prms.p = 4;                 /* How many threads to use.             */
    prms.T = ARGON_HASH_LEN;    /* How many bytes of output we want.    */
    prms.m = 2097000;           /* How many kibibytes of memory to use. */
    prms.t = 1;                 /* How many passes Argon2 should do.    */
    prms.v = 0x13;              /* Constant in Argon2 spec.             */
    prms.y = 0x02;              /* Constant in Argon2 spec.             */

    /* Zero-extend the password to 16 bytes including a null terminator.   */
    /* Len does not include the null terminator already placed by the GUI. */
    if(pw_bytes_for_zeroing > 0){
        memset(password + password_len, 0, pw_bytes_for_zeroing);
    }

    prms.P = password;

    /* Now construct the Argon2 Salt parameter.                         */
    /* Salt = S || BLAKE2B{64}(client's long-term public key)           */
    /* S is a random 8 byte string, so Salt length is 64+8 = 72 bytes.  */

    ranfile = fopen("/dev/urandom", "r");

    if(   (!ranfile)
       || (fread(argon2_salt_string, 1, ARGON_STRING_LEN, ranfile)
            != ARGON_STRING_LEN)
      )
    {
        printf("[ERR] Client: Reg failed to read urandom for salt string.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Call blake2b to get the second component of the salt parameter. */
    BLAKE2B_INIT(A_longterm->bits, PUBKEY_LEN, 0, 64, b2b_pubkey_output);

    /* Now construct the complete Salt parameter with the two components. */
    memcpy(Salt,     argon2_salt_string,  ARGON_STRING_LEN);
    memcpy(Salt + ARGON_STRING_LEN, b2b_pubkey_output,  64);

    prms.S = Salt;

    prms.len_P = PASSWORD_BUF_SIZ;
    prms.len_S = (8 + 64);  /* 8-byte string plus 64-byte output of blake2b. */
    prms.len_K = 0;         /* unused here, so set length to 0               */
    prms.len_X = 0;         /* unused here, so set length to 0               */

    printf("[DEBUG] Client: Before calling argon2 in REGISTER, parms:\n");
    printf("sizeof(argon2_parms) = %lu\n\n", sizeof(struct Argon2_parms));

    for(u32 i = 0; i < sizeof(struct Argon2_parms); ++i){
        printf("%03u ", *(((u8*)(&prms)) + i) );
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Password buffer of len %lu:\n", prms.len_P);
    for(u32 i = 0; i < prms.len_P; ++i){
        printf("%03u ", prms.P[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Salt buffer of len %lu:\n", prms.len_S);
    for(u32 i = 0; i < prms.len_S; ++i){
        printf("%03u ", prms.S[i]);
        if(((i+1) % 8 == 0) && i >= 7){
            printf("\n");
        }
    }
    printf("\n\n");

    Argon2_MAIN(&prms, argon2_output_tag);

    /* Registration step 3: Let V be the leftmost 32 bytes of Argon2's hash.
     *                      Use V as a key in ChaCha20, along with a
     *                      randomly-generated 16-byte Nonce (no counter)
     *                      to encrypt the private key.
     */

    /* Construct V. */
    memcpy(V, argon2_output_tag, chacha_key_len);

    /* Get the Nonce. */
    if(fread(chacha_nonce_buf, 1, LONG_NONCE_LEN, ranfile) != LONG_NONCE_LEN){
        printf("[ERR] Client: Reg failed to read urandom. Alert GUI.\n\n");
        status = 1;
        goto label_cleanup;
    }

    CHACHA20( temp_privkey.bits                  /* text - private key  */
             ,PRIVKEY_LEN                         /* text_len in bytes   */
             ,(u32*)chacha_nonce_buf              /* Nonce ptr           */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32)) /* nonceLen in uint32s */
             ,(u32*)V                             /* chacha Key ptr      */
             ,(u32)(chacha_key_len / sizeof(u32)) /* Key_len in uint32s  */
             ,encrypted_privkey_buf               /* output buffer ptr   */
            );

    /* Registration step 4: Save on the client's filesystem the necessary
     *                      cryptographic artifacts for a secure login:
     *                      ChaCha20 Nonce, Argon2 Salt string only, long-term
     *                      public key and long-term encrypted private key.
     *
     *                      May decide to also encrypt the long-term public
     *                      key in the future, but for now only private key.
     */

    user_save = fopen("../bin/user_save.dat", "w");

    if(!user_save){
        printf("[ERR] Client: Reg failed to open user_save. Alert GUI.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Prepare a buffer containing all the stuff to be saved for easy write. */

    memcpy(user_save_buf + save_offset, chacha_nonce_buf, LONG_NONCE_LEN);

    save_offset += LONG_NONCE_LEN;

    memcpy(user_save_buf + save_offset, encrypted_privkey_buf, PRIVKEY_LEN);

    save_offset += PRIVKEY_LEN;

    memcpy(user_save_buf + save_offset, A_longterm->bits, PUBKEY_LEN);

    save_offset += PUBKEY_LEN;

    memcpy(user_save_buf + save_offset, argon2_salt_string, 8);

    printf("[DEBUG] REG: save file buf (siz = %lu bytes) before writing it:\n\n"
           ,save_len
    );

    for(u64 i = 0; i < save_len; ++i){
        printf("%03u ", user_save_buf[i]);
        if(((i+1) % 8 == 0) && i >= 7){
            printf("\n");
        }
    }
    printf("\n\n");
    printf("[DEBUG] REG: It has 4 parts that are placed like so:\n\n");
    printf("[DEBUG] REG: ChaCha20  Nonce  : size = 16  bytes.\n");
    printf("[DEBUG] REG: Encrypted privkey: size = 40  bytes.\n");
    printf("[DEBUG] REG: Plaintext pubkey : size = 384 bytes.\n");
    printf("[DEBUG] REG: Argon Salt String: size = 8   bytes.\n\n");

    fwrite(user_save_buf, 1, save_len, user_save);

label_cleanup:

    free(A_longterm->bits);
    free(A_longterm);
    free(temp_privkey.bits);

    system("rm temp_privkey.dat");

    if(ranfile){
        fclose(ranfile);
    }

    if(user_save){
        fclose(user_save);
    }

    return status;
}

/* Special return code, other than 0 and 1, here is 10.
 * It means that the Rosetta server has told us to try logging again later
 * because there is no more space for any more logged in users right now.
 */

u8 login(u8* password, int password_len){

    u8  status = 0;
    u8* msg_buf = NULL;
    u8  reply_buf[MAX_TXT_LEN];

    u64*    reply_type_ptr = reply_buf;
    u64     msg_len;
    ssize_t reply_len;


    status = self_init(password, password_len);

    if(status){
        printf("[ERR] Client: Core initialization failed. Aborting login.\n\n");
        goto label_cleanup;
    }

    /* Begin the login handshake to transport our long-term public key in a
     * secure and authenticated fashion even without a session shared secret,
     * by using a different, extremely short-term pair of public / private keys
     * and shared secret that get destroyed right after this login handshake.
     */

    status = construct_msg_00(msg_buf, &msg_len);

    if(status){
        printf(\n"[ERR] Client: Couldn't construct MSG_00 for Login. Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Constructed MSG_00: %lu bytes\n", msg_len);



    status = send_payload(msg_buf, msg_len);

    if(status){
        printf("\n[ERR] Client: Couldn't send MSG_00 for Login. Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Transmitted MSG_00 to the Rosetta server.\n");



    status = grab_servers_reply(reply_buf, &reply_len);

    if(status){
        printf("\n[ERR] Client: Couldn't receive MSG_00 reply by server.\n\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Received reply to MSG_00: %lu bytes.\n", reply_len);



    if(*reply_type_ptr != PACKET_ID_02 && *reply_type_ptr != PACKET_ID_00){
        printf("[ERR] Client: Unexpected reply by the server to msg_00\n\n");
        goto label_cleanup;
    }

    /*------------------------------------------------------------------------*/

    if(*reply_type_ptr == PACKET_ID_00){

        /* Do not free the memory area pointed to by msg_buf just yet, as
         * process_msg_00 is a continued transmission, the second one in the
         * login handshake. It, on its own, will reallocate the buffer.
         */

        /* This processes msg_00 AND constructs msg_01. */

        status = process_msg_00(reply_buf, msg_buf, &msg_len);

        if(status){
            printf("[ERR] Client: process_msg_00 failed. Abort login.\n\n");
            goto label_cleanup;
        }
        printf("[OK]  Client: REPLY to MSG_00 is valid. Constructed MSG_01!\n");



/*  Now send the reply back to the Rosetta server:

================================================================================
|  packet ID 01   | Client's encrypted long-term PubKey |  HMAC authenticator  |
|=================|=====================================|======================|
| SMALL_FIELD_LEN |             PUBKEY_LEN              |   HMAC_TRUNC_BYTES   |
--------------------------------------------------------------------------------

*/
        status = send_payload(msg_buf, msg_len);

        if(status){
            printf("[ERR] Client: Sending MSG_01 failed.");
            goto label_cleanup;
        }
        printf("[OK]  Client: Sent MSG_01 to server.\n\n");


    }
    else{
        printf("[OK]  Client: Server told us to try login later.\n\n");

        status = process_msg_02(reply_buf);
        if (status){
            printf("[ERR] Client: process_msg_02 failed. Abort login.\n\n");
            goto label_cleanup;
        }
        status = 10;
	goto label_cleanup;
    }

    memset(reply_buf, 0, MAX_TXT_LEN);

    status = grab_servers_reply(reply_buf, &reply_len);

    if(status){
        printf("[ERR] Client: Couldn't receive a reply to msg_01.\n\n");
        goto label_cleanup;
    }

    printf("[OK]  Client: Received reply to msg_01: %lu bytes.\n", bytes_read);

    if(*reply_type_ptr == PACKET_ID_01){

        printf("[OK]  Client: Rosetta server told us login succeeded!\n\n");

        status = process_msg_01(reply_buf);

        if (status){
            printf("[ERR] Client: process_msg_01 failed. Abort login.\n\n");
            goto label_cleanup;
        }
    }

    else if(*reply_type_ptr == PACKET_ID_02){

        printf("[OK]  Client: Rosetta server told us to try later, full!\n\n");

        status = process_msg_02(msg_buf);

        if (status){
            printf("[ERR] Client: process_msg_02 failed. Abort login.\n\n");
            goto label_cleanup;
        }

        status = 10;
	goto label_cleanup;
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_01.\n\n");
        status = 1;
	goto label_cleanup;
    }

    printf("\n\n\n******** LOGIN COMPLETED *********\n\n\n");

label_cleanup:

    if(msg_buf){
        free(msg_buf);
    }

    return status;
}

u8 make_new_chatroom(unsigned char* roomid, int roomid_len,
                     unsigned char* userid, int userid_len
                    )
{
    u64 userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64 roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len;

    u8 status = 0;
    u8 msg_buf[MAX_TXT_LEN];

    ssize_t bytes_read;

    /* Zero-extend the userID to 8 bytes including a null terminator.       */
    /* Len does not include the null terminator already placed by the GUI.  */
    if(userid_bytes_for_zeroing > 0){
        memset(userid + userid_len, 0, userid_bytes_for_zeroing);
    }

    /* Do the same for roomID.   */
    if(roomid_bytes_for_zeroing > 0){
        memset(roomid + roomid_len, 0, roomid_bytes_for_zeroing);
    }

    /* Send a request to the Rosetta server to create a new chatroom. */

    /* Expected replies: msg_10=OK, msg_11=NoSpace. */
    status = construct_msg_10(userid, roomid);

    if(status){
        printf("[ERR] Client: Couldn't construct msg_10\n\n");
	goto label_cleanup;
    }

    /* Capture the server's reply. */

    memset(msg_buf, 0, MAX_TXT_LEN);

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    /* if(status) { ... }  after saying receive_msg_reply(), not recv(). */
    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't recv() a reply to msg_10.\n\n");
        perror("errno = ");
	status = 1;
        goto label_cleanup;
    }

    printf("[OK]  Client: Received reply to msg_10: %lu bytes.\n", bytes_read);

    if( *((u64*)msg_buf) == PACKET_ID_10 ){

        status = process_msg_10(msg_buf);

        if (status){
            printf("[ERR] Client: process_msg_10 failed.\n\n");
            goto label_cleanup;
        }

        printf("[OK]  Client: Rosetta told us our room has been created!\n\n");
    }

    else if( *((u64*)msg_buf) == PACKET_ID_11 ){

        status = process_msg_11(msg_buf);

        if (status){
            printf("[ERR] Client: process_msg_11 failed.\n\n");
            goto label_cleanup;
        }

        printf("[OK]  Client: Rosetta told us: try later, room is full!\n\n");

        status = 10;
	goto label_cleanup;
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_10.\n\n");
        status = 1;
	goto label_cleanup;
    }

    printf("\n\n\n******** ROOM CREATION SUCCESSFUL *********\n\n\n");

    /* Here is one of 2 possible places to start polling. So start it.
     * Basically an infinite loop in a separate running thread that sends a
     * polling request to the Rosetta server every 0.2 seconds or so, asking for
     * info about undisplayed messages by others, a room participant having left
     * the chatroom or the owner of the chatroom having deleted it, etc.
     *
     * Ideally the vastly most common case of there not being anything for us
     * to receive shouldn't need to lock the GUI thread (for too long).
     */

    /* ALSO, here is one of 2 possible places where GUI renders the graphics
     * for the messages sub-window and "exit room" button. Render them.
     */

    start_polling_thread();

/* Unused for now but still have a label for completeness. */
label_cleanup:

    return status;
}

u8 join_chatroom(unsigned char* roomid, int roomid_len,
                 unsigned char* userid, int userid_len
                )
{
    u64 userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64 roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len;
    u64 msg_len;

    u8 status = 0;
    u8 msg_buf[MAX_TXT_LEN];

    ssize_t bytes_read;

    /* Zero-extend the userID to 8 bytes including a null terminator.       */
    /* Len does not include the null terminator already placed by the GUI.  */
    if(userid_bytes_for_zeroing > 0){
        memset(userid + userid_len, 0, userid_bytes_for_zeroing);
    }

    /* Do the same for roomID.   */
    if(roomid_bytes_for_zeroing > 0){
        memset(roomid + roomid_len, 0, roomid_bytes_for_zeroing);
    }

    /* Send a request to the Rosetta server to create a new chatroom. */

    /* Expected reply: msg_20=OK */
    status = construct_msg_20(userid, roomid);

    /* bad msg_20 construction. abort. */
    if(status){
        printf("[ERR] Client: Could not construct msg_20 to join a room!\n\n");
	goto label_cleanup;
    }

    /* Capture the server's reply. */
    memset(msg_buf, 0, MAX_TXT_LEN);

    printf("Waiting for the server to reply with PACKET_ID = 20.\n");

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't recv() a reply to msg_20.\n\n");
        perror("errno = ");
        status = 1;
	goto label_cleanup;
    }

    printf("[OK]  Client: Received reply to msg_20: %lu bytes.\n", bytes_read);

    if( *((u64*)msg_buf) == PACKET_ID_20 ){

        msg_len = bytes_read;

        status = process_msg_20(msg_buf, msg_len);

        if (status){
            printf("[ERR] Client: process_msg_20 failed.\n\n");
            goto label_cleanup;
        }

	printf("[OK]  Client: Rosetta told us we've now joined the room!\n\n");
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_20.\n\n");
        status = 1;
	goto label_cleanup;
    }

    printf("\n\n\n******** ROOM JOINED SUCCESSFULLY *********\n\n\n");

    /* Here is one of 2 possible places to start polling. So start it.
     * Basically an infinite loop in a separate running thread that sends a
     * polling request to the Rosetta server every 0.2 seconds or so, asking for
     * info about undisplayed messages by others, a room participant having left
     * the chatroom or the owner of the chatroom having deleted it, etc.
     *
     * Ideally the vastly most common case of there not being anything for us
     * to receive shouldn't need to lock the GUI thread (for too long).
     */

    /* ALSO, here is one of 2 possible places where GUI renders the graphics
     * for the messages sub-window and "exit room" button. Render them.
     */

    start_polling_thread();

/* Unused for now but keep the label for completeness. */
label_cleanup:

    return status;

