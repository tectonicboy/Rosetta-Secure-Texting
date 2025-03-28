#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#define SERVER_IP_ADDR "192.168.8.21"

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

/* Linux Sockets API related globals. */
const int port = SERVER_PORT;

int own_socket_fd = -1;
const int optval1 = 1;


const socklen_t server_addr_len = sizeof(struct sockaddr_in);

struct sockaddr_in servaddr;

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
   
    u8 status; 
    
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

    u8 status = 1;
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

    memset(&prms, 0, sizeof(struct Argon2_parms));

    /* Initialize data structures for maintaining global state & bookkeeping. */
    memset(roommates,           0, roommates_arr_siz * sizeof(struct roommate));
    memset(own_privkey_buf,     0, PRIVKEY_LEN);
    memset(temp_handshake_buf,  0, TEMP_BUF_SIZ);

    /* Load user's public key, decrypt and load user's private key. */

    savefile = fopen("../bin/user_save.dat", "r"); 
    
    if(savefile == NULL){
        printf("[ERR] Client: couldn't open the user's save file. Aborting.\n");
        return 0;
    }       
    
    /* Read savefile in the same order that Registration writes it in. */

    /* First is Nonce for decrypting the saved private key. */
    if(fread(saved_nonce, 1, LONG_NONCE_LEN, savefile) != LONG_NONCE_LEN){
        printf("[ERR] Client: couldn't get nonce from savefile[0].\n");
        status = 0;
        goto label_cleanup;
    }

    /* Second is the user's long-term private key in encrypted form. */
    if(fread(saved_privkey, 1, PRIVKEY_LEN, savefile) != PRIVKEY_LEN){
        printf("[ERR] Client: couldn't get encr. privkey from savefile[1].\n");
        status = 0;
        goto label_cleanup;
    }

    /* Third is the user's long-term public key non-encrypted. */
    if(fread(saved_pubkey, 1, PUBKEY_LEN, savefile) != PUBKEY_LEN){
        printf("[ERR] Client: couldn't get pubkey from savefile[2].\n");
        status = 0;
        goto label_cleanup;
    }

    /* Fourth and last is the 8-byte string - part of Argon2 parameter S. */
    if(fread(saved_string, 1, ARGON_STRING_LEN, savefile) != ARGON_STRING_LEN){
        printf("[ERR] Client: couldn't get string from savefile[3].\n");
        status = 0;
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
        status = 0;
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
        status = 0;
        goto label_cleanup;
    }

    /* 320-bit prime exactly dividing M-1, making M cryptographically strong. */
    Q = get_BIGINT_from_DAT(320, "../bin/saved_Q.dat", 320,  MAX_BIGINT_SIZ);

    if(Q == NULL){
        printf("[ERR] Client: Failed to get Q from DAT file.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* Diffie-Hellman generator G = 2^((M-1)/Q) */
    G = get_BIGINT_from_DAT(3072, "../bin/saved_G.dat", 3071, MAX_BIGINT_SIZ);

    if(G == NULL){
        printf("[ERR] Client: Failed to get G from DAT file.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_BIGINT_from_DAT(3072, "../bin/saved_Gm.dat", 3071, MAX_BIGINT_SIZ);

    if(Gm == NULL){
        printf("[ERR] Client: Failed to get Gm from DAT file.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* Grab the server's public key. */
    server_pubkey = 
    get_BIGINT_from_DAT(3072, "../bin/server_pubkey.dat", 3071, MAX_BIGINT_SIZ);

    if(server_pubkey == NULL){
        printf("[ERR] Client: Failed to get server pubkey from DAT file.\n\n");
        status = 0;
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
        status = 0;
        goto label_cleanup; 
    } 

    /* Initialize the socket before the connect() call. */
    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(own_socket_fd == -1) {
        printf("[ERR] Client: socket() failed. Terminating.\n");
        perror("errno:");
        return 0;
    }

    if(
        setsockopt(
           own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval1, sizeof(optval1)
        ) 
        != 0
    )
    {
        printf("[ERR] Client: set socket option failed.\n\n");
    }

    printf("[OK]  Client: Socket file descriptor obtained!\n");

    /* Connect to the Rosetta server. */
    
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        == -1 
      )
    {
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        perror("connect() failed, errno: ");
        return 0;
    }
    
    printf("[OK]  Client: Connect() call finished, won't be re-attempted.\n");

    
label_cleanup:

    fclose(savefile);

    if(calculated_A != NULL){
        free(calculated_A->bits);
        free(calculated_A);
    }

    return status;
}

void release_handshake_memory_region(){

    bigint* temp_ptr;

    temp_ptr = (bigint*)temp_handshake_buf;
    free(temp_ptr->bits);

    temp_ptr = (bigint*)(temp_handshake_buf + sizeof(bigint));
    free(temp_ptr->bits);

    /* If we WEREN'T told to try login later right after msg_00, but rather 
     * after msg_01, which means rosetta is full right now, then the client
     * software will have placed a third bigint object in the memory region
     * at the very least - free its bit buffer too before zeroing it out.
     */
    if(handshake_memory_region_state == 2){
        temp_ptr = (bigint*)(temp_handshake_buf + (2 * sizeof(bigint)));
        free(temp_ptr->bits);
    }

    memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);

    temp_handshake_memory_region_isLocked = 0;     
    handshake_memory_region_state = 0;

    printf("[OK]  Client: Handshake memory region has been released!\n\n");

    return;
}

/* A user requested to be logged in Rosetta:

    Client ----> Server

================================================================================
|        PACKET_ID_00         |   Client's short-term public key in the clear  |
|=============================|================================================|
|       SMALL_FIELD_LEN       |                    PUBKEY_LEN                  |
--------------------------------------------------------------------------------

*/
u8 construct_msg_00(void){

    bigint* A_s;
    bigint temp_privkey;

    u8 status = 1;
    
    const u64 msg_len = SMALL_FIELD_LEN + PUBKEY_LEN;
    u8 msg_buf[msg_len];

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
    temp_privkey.free_bits = MAX_BIGINT_SIZ - temp_privkey.used_bits;

    memset(temp_handshake_buf, 0, PRIVKEY_LEN);

    memcpy(temp_handshake_buf, &temp_privkey, sizeof(bigint));



    /* Interface generating a pub_key still needs priv_key in a file. TODO. */
    save_BIGINT_to_DAT("temp_privkey_DAT.dat", &temp_privkey);
  
    A_s = gen_pub_key(PRIVKEY_LEN, "temp_privkey_DAT.dat", MAX_BIGINT_SIZ);
    


    /* Place our short-term pub_key also in the locked memory region. */
    memcpy(temp_handshake_buf + sizeof(bigint), A_s, sizeof(bigint));
   
    handshake_memory_region_state = 1;

    /* Construct and send the MSG buffer to the TCP server. */
    
    *((u64*)(msg_buf)) = PACKET_ID_00;
    
    memcpy(msg_buf + SMALL_FIELD_LEN, A_s->bits, PUBKEY_LEN);


    /* Send the packet. */
    if(send(own_socket_fd, msg_buf, msg_len, 0) != msg_len){
        printf("[ERR] Client: Couldn't send initial login transmission.\n");
        printf("[ERR]         Aborting Login...\n\n");
        status = 0;
        goto label_cleanup;
    }
    
    printf("[OK]  Client: MSG_00 sent. Server should get %lu bytes\n", msg_len);

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
u8 process_msg_00(u8* msg_buf){

    u64 handshake_buf_key_offset;
    u64 handshake_buf_nonce_offset;
    const u64 B = 64;
    const u64 L = 64;
    const u64 reply_len = SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES;

    u32 tempbuf_write_offset;
    u32 shared_secret_read_offset;
    u32 HMAC_reply_offset = SMALL_FIELD_LEN + PUBKEY_LEN;

    bigint  X_s;
    bigint  B_s;
    bigint  B_sM;
    bigint  zero;
    bigint *a_s = (bigint*)(temp_handshake_buf);

    u8 status = 1;    
    u8 K0[B];
    u8 ipad[B];
    u8 opad[B];
    u8 K0_XOR_ipad_TEXT[B + PUBKEY_LEN];
    u8 BLAKE2B_output[L];   
    u8 last_BLAKE2B_input[B + L];
    u8 K0_XOR_ipad[B];
    u8 K0_XOR_opad[B];
    u8 reply_buf[reply_len];
    u8 auth_status;
    u8 auth_buf[INIT_AUTH_LEN + SIGNATURE_LEN];

    memset(K0,                  0, B);
    memset(ipad,                0, B);
    memset(opad,                0, B);
    memset(K0_XOR_ipad_TEXT,    0, B + PUBKEY_LEN);
    memset(BLAKE2B_output,      0, L);   
    memset(last_BLAKE2B_input,  0, B + L);
    memset(K0_XOR_ipad,         0, B);
    memset(K0_XOR_opad,         0, B);
    memset(reply_buf,           0, reply_len);
    memset(auth_buf,            0, INIT_AUTH_LEN + SIGNATURE_LEN);

    /* Grab the server's short-term public key from the transmission.        */
    /* Another bigint construction by hand, ugly!! Find time for a function. */
    B_s.bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    memcpy(B_s.bits, msg_buf + SMALL_FIELD_LEN, PUBKEY_LEN);
    B_s.size_bits = MAX_BIGINT_SIZ;
    B_s.used_bits = get_used_bits(B_s.bits, PUBKEY_LEN);
    B_s.free_bits = B_s.size_bits - B_s.used_bits;
    
    /* Compute a short-term shared secret with the server, extract a pair of
     * symmetric bidirectional keys and the symmetric ChaCha Nonce, as well as
     * the unused part of the shared secret, of which the server has computed
     * a cryptographic signature, which we need to verify for authentication.
     *
     *       X_s   = B_s^a_s mod M   <--- Montgomery Form of B_s.
     *
     *       KAB_s = X_s[0  .. 31 ]
     *       KBA_s = X_s[32 .. 63 ]
     *       Y_s   = X_s[64 .. 95 ]construct_msg_00
     *       N_s   = X_s[96 .. 107]  <--- 12-byte Nonce for ChaCha20.
     */
    
    bigint_create(&X_s,  MAX_BIGINT_SIZ, 0);
    bigint_create(&zero, MAX_BIGINT_SIZ, 0);
    bigint_create(&B_sM, MAX_BIGINT_SIZ, 0);
    
    Get_Mont_Form(&B_s, &B_sM, M);
    
    /* Check the other side's public key for security flaws and consistency. */   
    if(   ((bigint_compare2(&zero, &B_s)) != 3) 
        || 
          ((bigint_compare2(M, &B_s)) != 1)
        //||
        // (check_pubkey_form(&B_sM, M, Q) == 0) 
      )
    {
        printf("[ERR] Client: Server's short-term public key is invalid.\n");
        printf("              Its info and ALL %u bits:\n\n", B_s.size_bits);
        bigint_print_info(&B_s);
        bigint_print_all_bits(&B_s);
        status = 0;
        goto label_cleanup;
    }     

    /* X_s = B_s^a_s mod M */
    MONT_POW_modM(&B_sM, a_s, M, &X_s);

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
           ,msg_buf  + (SMALL_FIELD_LEN + PUBKEY_LEN)
           ,SIGNATURE_LEN
          );
    
    /* Validate the signature of the unused part of the shared secret, Y_s. */
    auth_status = authenticate_server(auth_buf, INIT_AUTH_LEN, INIT_AUTH_LEN);

    if(auth_status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_00. Drop.\n\n");
        status = 0;
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
     printf("?? 8 \n");
    shared_secret_read_offset += SESSION_KEY_LEN;
    tempbuf_write_offset      += SESSION_KEY_LEN;
    
    /* Key KBA_s */
    memcpy( temp_handshake_buf + tempbuf_write_offset
           ,X_s.bits + shared_secret_read_offset
           ,SESSION_KEY_LEN
          );
           printf("?? 9 \n");
    shared_secret_read_offset += SESSION_KEY_LEN;
    tempbuf_write_offset      += SESSION_KEY_LEN;      
    
    /* Section of shared secret on which we'll compute Schnorr signatures. */
    memcpy( temp_handshake_buf + tempbuf_write_offset
        ,X_s.bits + shared_secret_read_offset
        ,INIT_AUTH_LEN
       );
    printf("?? 10 \n");
    shared_secret_read_offset += INIT_AUTH_LEN;
    tempbuf_write_offset      += INIT_AUTH_LEN;  
    
    /* short-term symmetric Nonce for encrypting/decrypting with ChaCha20 */
    memcpy( temp_handshake_buf + tempbuf_write_offset
        ,X_s.bits + shared_secret_read_offset
        ,SHORT_NONCE_LEN
       );
      printf("?? 11 \n");
    /* Ready to start constructing the reply buffer to the server. */ 
        
    *((u64*)(reply_buf)) = PACKET_ID_01;
       
    /*  Client uses KAB_s as key and 12-byte N_s as Nonce in ChaCha20 to
     *  encrypt its long-term public key A, producing the key A_x.
     *
     *  Sends that encrypted long-term public key to the Rosetta server.
     */
    handshake_buf_nonce_offset =  
                (3 * sizeof(bigint)) + (2 * SESSION_KEY_LEN) + INIT_AUTH_LEN;
                                                            
    handshake_buf_key_offset = 3 * sizeof(bigint);
    
    printf("[DEBUG] Client: Real public key before encrypting it:\n");
    bigint_print_info(&own_pubkey);
    bigint_print_bits(&own_pubkey);

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
    CHACHA20( own_pubkey.bits
             ,PUBKEY_LEN
             ,(u32*)(temp_handshake_buf + handshake_buf_nonce_offset)
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32))       
             ,(u32*)(temp_handshake_buf + handshake_buf_key_offset)
             ,(u32)(SESSION_KEY_LEN / sizeof(u32))
             ,reply_buf + SMALL_FIELD_LEN
            );

    printf("[DEBUG] Client: ChaCha to encrypt client's long-term pubkey:\n");
    printf("RESULTED IN: client's encrypted pubkey:\n");

    for(u64 i = 0; i < PUBKEY_LEN; ++i){
        printf("%03u ", (reply_buf + SMALL_FIELD_LEN)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    printf("input SHORT nonce was:\n");

    for(u64 i = 0; i < SHORT_NONCE_LEN; ++i){
        printf("%03u ", (temp_handshake_buf + handshake_buf_nonce_offset)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    printf("Input chacha key of SESSION_KEY_LEN was:\n");

    for(u64 i = 0; i < SESSION_KEY_LEN; ++i){
        printf("%03u ", (temp_handshake_buf + handshake_buf_key_offset)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    /* Increment the Nonce to not reuse it when decrypting our user index.  */
    /* It's not a BigInt in there but just increment to leftmost 64 bits.   */
    /* And it should have the same effect unless we lucked out with all 1s. */
    /* But generating 64 1s in a row with no 0s should be extremely rare.   */       
    ++(*((u64*)(temp_handshake_buf + handshake_buf_nonce_offset)));
       
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

    printf("[DEBUG] Client: HMAC Step 3 produced K0: 64 bytes:\n");

    for(u32 i = 0; i < B; ++i){
        printf("%03u ", K0[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Step 4 of HMAC construction */
    for(u64 i = 0; i < B; ++i){
        K0_XOR_ipad[i] = (K0[i] ^ ipad[i]);
    }       

    printf("[DEBUG] Client: HMAC Step 4 produced K0_XOR_ipad: 64 bytes:\n");

    for(u32 i = 0; i < B; ++i){
        printf("%03u ", K0_XOR_ipad[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* step 5 of HMAC construction */
    memcpy(K0_XOR_ipad_TEXT, K0_XOR_ipad, B);
    memcpy(K0_XOR_ipad_TEXT + B, reply_buf + SMALL_FIELD_LEN, PUBKEY_LEN);
    
    printf("[DEBUG] Client: HMAC Step 5 produced K0_XOR_ipad_TEXT: 448 bytes:\n");

    for(u32 i = 0; i < B + PUBKEY_LEN; ++i){
        printf("%03u ", K0_XOR_ipad_TEXT[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* step 6 of HMAC construction */
    /* Call BLAKE2B on K0_XOR_ipad_TEXT */ 
    BLAKE2B_INIT(K0_XOR_ipad_TEXT, B + PUBKEY_LEN, 0, L, BLAKE2B_output);       

    printf("[DEBUG] Client: HMAC Step 6 produced BLAKE2B_output: 64 bytes:\n");

    for(u32 i = 0; i < L; ++i){
        printf("%03u ", BLAKE2B_output[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Step 7 of HMAC construction */
    for(u64 i = 0; i < B; ++i){
        K0_XOR_opad[i] = (K0[i] ^ opad[i]);
    }   
    
    printf("[DEBUG] Client: HMAC Step 7 produced K0_XOR_opad: 64 bytes:\n");

    for(u32 i = 0; i < B; ++i){
        printf("%03u ", K0_XOR_opad[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Step 8 of HMAC construction */
    /* Combine first BLAKE2B output buffer with K0_XOR_opad. */
    /* B + L bytes total length */
    memcpy(last_BLAKE2B_input + 0, K0_XOR_opad,    B);
    memcpy(last_BLAKE2B_input + B, BLAKE2B_output, L);    
    
   printf("[DEBUG] Client: HMAC Step 8 produced last_BLAKE2B_input: 192 bytes:\n");

    for(u32 i = 0; i < B + L; ++i){
        printf("%03u ", last_BLAKE2B_input[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Step 9 of HMAC construction */ 
    /* Call BLAKE2B on the combined buffer in step 8. */
    BLAKE2B_INIT(last_BLAKE2B_input, B + L, 0, L, BLAKE2B_output);

   printf("[DEBUG] Client: HMAC Step 9 produced BLAKE2B_output: 64 bytes:\n");

    for(u32 i = 0; i < L; ++i){
        printf("%03u ", BLAKE2B_output[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Take the HMAC_TRUNC_BYTES leftmost bytes to form the HMAC output. */
    memcpy(reply_buf + HMAC_reply_offset, BLAKE2B_output, HMAC_TRUNC_BYTES);

    printf("[DEBUG] Client: Placed these 8 bytes of HMAC in packet:\n\n");

    for(u32 i = 0; i < HMAC_TRUNC_BYTES; ++i){
        printf("%03u ", BLAKE2B_output[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");  

/*  Now send the reply back to the Rosetta server:

================================================================================
|  packet ID 01   | Client's encrypted long-term PubKey |  HMAC authenticator  |
|=================|=====================================|======================|
| SMALL_FIELD_LEN |             PUBKEY_LEN              |   HMAC_TRUNC_BYTES   |
--------------------------------------------------------------------------------

*/

    printf("[DEBUG] Client: Printing msg_01 of length %lu BYTES:\n", reply_len);

    for(u64 i = 0; i < reply_len; ++i){
        printf("%03u ", (reply_buf)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    if(send(own_socket_fd, reply_buf, reply_len, 0) == -1){
        printf("[ERR] Client: Couldn't send second login transmission.\n");
        printf("[ERR]         Aborting Login...\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Sent second login transmission!\n");
    }
    
label_cleanup:
   
    free(X_s.bits);
    free(zero.bits);
    free(B_sM.bits);
    
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
    
    u8 status = 1;

    /* Validate the incoming signature with the server's long-term public key
     * on packet_ID_01 (for now... later it will be of the whole payload).
     */    
    
    status = authenticate_server(msg, SMALL_FIELD_LEN, (2 * SMALL_FIELD_LEN));

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_01. Drop.\n");
        printf("              Tell GUI to tell user login went badly.\n\n");
        status = 0;
        goto label_cleanup;           
    }
    
    /* Signature is valid! Can locate our index, decrypt it and save it. */
    
    nonce_offset = (3 * sizeof(bigint)) + (2 * SESSION_KEY_LEN) + INIT_AUTH_LEN; 
    
    key_offset = (3 * sizeof(bigint)) + (1 * SESSION_KEY_LEN);  
                 
    CHACHA20( msg + SMALL_FIELD_LEN                    /* text - encrypted ix */
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
 
    release_handshake_memory_region();
    
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

    u8 status;

    /* Validate the incoming signature with the server's long-term public key
     * on packet_ID_02.
     */    
    
    status = authenticate_server(msg, SMALL_FIELD_LEN, SMALL_FIELD_LEN);    

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_02. Drop.\n\n");
        status = 0;       
    }
    
    release_handshake_memory_region();
    
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
                    ,unsigned char* requested_roomid )
{
    bigint one;
    bigint aux1;
    
    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 send_len              = signed_len + SIGNATURE_LEN;

    FILE* ran_file = NULL;

    u8 status = 1;
    u8 send_K[ONE_TIME_KEY_LEN];
    u8 send_buf[send_len];
    u8 roomID_userID[2 * SMALL_FIELD_LEN];   
     
    memset(send_K,        0, ONE_TIME_KEY_LEN);
    memset(send_buf,      0, send_len);
    memset(roomID_userID, 0, 2 * SMALL_FIELD_LEN);   

    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

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
        status = 0;
        goto label_cleanup;
    }       

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_10 creation.\n");
        status = 0;
        goto label_cleanup;
    }
       
    /* Increment nonce as many times as the saved counter says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }    
    
    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */
    
    CHACHA20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,send_buf + (2 * SMALL_FIELD_LEN)     /* output target buffer    */
            );    
    
    /* Maintain nonce's symmetry on both server and client with counters. */
    ++server_nonce_counter;
    
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    
    /* Prepare the buffer containing the user_ID and room_ID for encryption. */
    memcpy(roomID_userID, requested_roomid, SMALL_FIELD_LEN);   
    memcpy(roomID_userID + SMALL_FIELD_LEN, requested_userid, SMALL_FIELD_LEN);
    
    /* Encrypt the user's requested user_ID and room_ID for their new room. */
    
    CHACHA20( roomID_userID                        /* text: one-time key K    */
             ,(2 * SMALL_FIELD_LEN)                /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,send_buf + sendbuf_roomID_offset     /* output target buffer    */
            );        

    ++server_nonce_counter;

    /* Construct the first 2 parts of this packet - identifier and user_ix. */
    
    *((u64*)(send_buf)) = PACKET_ID_10;
    
    *((u64*)(send_buf + SMALL_FIELD_LEN)) = own_ix;
    
    /* Now calculate a cryptographic signature of the whole packet's payload. */

    printf("[DEBUG] Client: Calling signature_generate with:\n");

    printf("[DEBUG] Server: signed things of length %lu:\n", signed_len);

    for(u64 i = 0; i < signed_len; ++i){
        printf("%03u ", *(send_buf + i) );
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Also, client's real long-term public key:\n");
    bigint_print_info(&own_pubkey);
    bigint_print_bits(&own_pubkey);

    Signature_GENERATE( M, Q, Gm, send_buf, signed_len
                       ,(send_buf + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

    /* Ready to send the constructed packet to the Rosetta server now. */

    if(send(own_socket_fd, send_buf, send_len, 0) == -1){
        printf("[ERR] Client: Couldn't send constructed packet 10.\n");
        printf("              Which is the request to create a new room\n");
        printf("              Tell GUI to tell the user about this!\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Sent request to create a new chatroom!\n\n");
    }

label_cleanup:
    
    if(ran_file){
        fclose(ran_file);
    }
    
    free(one.bits);
    free(aux1.bits);
    
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

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_11. Drop.\n");
        printf("              Telling GUI to tell user something's wrong.\n\n");
        status = 0;       
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

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_10. Drop.\n");
        printf("              Telling GUI to tell user something's wrong.\n\n");
        status = 0;       
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
                    ,unsigned char* requested_roomid )
{
    bigint one; 
    bigint aux1;
    
    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 send_len              = signed_len + SIGNATURE_LEN;

    FILE* ran_file = NULL;

    u8 status = 1;
    u8 send_K[ONE_TIME_KEY_LEN];
    u8 send_buf[send_len];
    u8 roomID_userID[2 * SMALL_FIELD_LEN];   

    memset(send_K,        0, ONE_TIME_KEY_LEN);
    memset(send_buf,      0, send_len);
    memset(roomID_userID, 0, 2 * SMALL_FIELD_LEN);       

    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

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
        status = 0;
        goto label_cleanup;
    }       

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_20 creation.\n");
        status = 0;
        goto label_cleanup;
    }
    
    /* Increment nonce as many times as the saved counter says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }    
    
    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */
    
    CHACHA20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,send_buf + (2 * SMALL_FIELD_LEN)     /* output target buffer    */
            );    
    
    /* Maintain nonce's symmetry on both server and client with counters. */
    ++server_nonce_counter;
    
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    
    /* Prepare the buffer containing the user_ID and room_ID for encryption. */
    memcpy(roomID_userID, requested_roomid, SMALL_FIELD_LEN);   
    memcpy(roomID_userID + SMALL_FIELD_LEN, requested_userid, SMALL_FIELD_LEN);

    /* Encrypt the user's requested user_ID and room_ID for the joining room. */
    
    CHACHA20( roomID_userID                        /* text: one-time key K    */
             ,(2 * SMALL_FIELD_LEN)                /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,send_buf + sendbuf_roomID_offset     /* output target buffer    */
            );        

    ++server_nonce_counter;

    /* Construct the first 2 parts of this packet - identifier and user_ix. */
    
    *((u64*)(send_buf)) = PACKET_ID_10;
    
    *((u64*)(send_buf + SMALL_FIELD_LEN)) = own_ix;
    
    /* Now calculate a cryptographic signature of the whole packet's payload. */
    
    Signature_GENERATE( M, Q, Gm, send_buf, signed_len
                       ,(send_buf + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

    /* Ready to send the constructed packet to the Rosetta server now. */

    if(send(own_socket_fd, send_buf, send_len, 0) == -1){
        printf("[ERR] Client: Couldn't send constructed packet 20.\n");
        printf("              Which is the request to join an existing room\n");
        printf("              Tell GUI to tell the user about this!\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Sent request to join an existing chatroom!\n\n");
    }

    /* Now the Rosetta server:
     * 
     *      - Sends us packet_20 with its Associated Data containing 1 or more 
     *        pairs of (guest_user_ID + guest_public_key), enabling us to talk
     *        in a secure and authenticated fashion to all current room guests.
     *
     *        OR
     *      
     *      - Sends us nothing, which we catch by waiting for X seconds in a
     *        special reply awaiting thread. While waiting, have the GUI keep
     *        a "waiting for reply" message displayed somewhere so the user
     *        doesn't thing Rosetta is bugged or frozen or something.
     */
     
label_cleanup:
    
    if(ran_file){
        fclose(ran_file);
    }
    
    free(one.bits);
    free(aux1.bits);
    
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

    u8  status = 1;
    u8  recv_K[ONE_TIME_KEY_LEN];
    u8* buf_decrypted_AD = NULL;

    u64 num_current_guests = *(u64*)(msg + SMALL_FIELD_LEN + ONE_TIME_KEY_LEN);
    u64 guest_info_slot_siz = (SMALL_FIELD_LEN + PUBKEY_LEN);
    u64 recv_type20_AD_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 recv_type20_AD_len;
    u64 recv_type20_AD_len_expected;
    u64 recv_type20_signed_len;

    memset(recv_K, 0, ONE_TIME_KEY_LEN);

    bigint_create(&temp_shared_secret, MAX_BIGINT_SIZ, 0);
    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

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
        status = 0;
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

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_20. Drop.\n");
        printf("              Tell GUI to tell user to try join again.\n\n");
        status = 0;   
        goto label_cleanup;    
    }
    
    /* Next, use shared secret with server to decrypt KC with KBA chacha key. */
    /* This yields us the key to in turn decrypt the Associated Data with.    */
    
    /* Increment nonce as many times as the saved counter with server says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }    

    
    CHACHA20( (msg + SMALL_FIELD_LEN)              /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KBA)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output target buffer    */
            );        
    
    ++server_nonce_counter;
    
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);     

    /* Now use the obtained one-time key K to decrypt the room guests' info. */
    
    CHACHA20( (msg + recv_type20_AD_offset)        /* text: one-time key K    */
             ,recv_type20_AD_len                   /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* Nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,buf_decrypted_AD                     /* output target buffer    */
            );  
        
    ++server_nonce_counter;
     
    /* Now initialize the global state for keeping information about guests in
     * the chatroom we're currently in and process this message's associated
     * data, filling out a guest descriptor structure for each guest in it. 
     */ 
    memset(roommates, 0, roommates_arr_siz * sizeof(struct roommate)); 
    next_free_roommate_slot = 0;
    roommate_slots_bitmask = 0;
    num_roommates = num_current_guests;
    next_free_roommate_slot = num_current_guests;

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
        this_pubkey->free_bits =this_pubkey->size_bits - this_pubkey->used_bits;

        bigint_create(&(roommates[i].guest_pubkey_mont), MAX_BIGINT_SIZ, 0);  
        Get_Mont_Form(this_pubkey, &(roommates[i].guest_pubkey_mont), M);
        
        roommates[i].guest_nonce_counter = 0;
        
        bigint_nullify(&temp_shared_secret);

        /* Now compute a shared secret with the i-th guest to get our pair of
         * bidirectional session keys KAB, KBA and the symmetric ChaCha nonce. 
         */
        MONT_POW_modM(
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
    }

label_cleanup:
    
    free(one.bits);
    free(aux1.bits);
    free(temp_shared_secret.bits);

    if(buf_decrypted_AD) { 
        free(buf_decrypted_AD);
    }    

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
u8 process_msg_21(u8* msg){

    u64 signed_len;
    u64 new_guest_info_offset = ONE_TIME_KEY_LEN + SMALL_FIELD_LEN;
    u64 guest_ix;
    const u64 new_guest_info_len = SMALL_FIELD_LEN + PUBKEY_LEN;

    bigint  one; 
    bigint  aux1;
    bigint  temp_shared_secret;
    bigint* this_pubkey;

    u8 status = 1;
    u8 recv_K[ONE_TIME_KEY_LEN];
    u8 buf_decrypted_guest_info[new_guest_info_len];

    memset(recv_K, 0, ONE_TIME_KEY_LEN);
    memset(buf_decrypted_guest_info, 0, new_guest_info_len);

    bigint_create(&temp_shared_secret, MAX_BIGINT_SIZ, 0);
    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

    /* First, verify the Schnorr signature in the packet, in order to validate
     * the authenticity of the message, ensure it was not edited in trasnit and
     * that it really is coming from the Rosetta server.
     */
    signed_len = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + PUBKEY_LEN;

    status = authenticate_server(msg, signed_len, signed_len);    

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_21. Drop.\n");
        status = 0;   
        goto label_cleanup;    
    }  

    /* Next, use shared secret with server to decrypt KC with KBA chacha key. */
    /* This yields us the key to in turn decrypt the new guest info with.    */
     
    /* Increment nonce as many times as the saved counter with server says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }    

    /* DECRYPTING the one time key KC back into K.                            */
    CHACHA20( (msg + SMALL_FIELD_LEN)              /* text: one-time key KC   */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KBA)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output: chacha key K    */
            );        
    
    ++server_nonce_counter;
    
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);     

    /* Now use the obtained one-time key K to decrypt the room guests' info. */
    
    /* DECRYPTING new guest's information.                                    */
    CHACHA20( (msg + new_guest_info_offset)        /* text: one-time key K    */
             ,new_guest_info_len                   /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* Nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,buf_decrypted_guest_info             /* output target buffer    */
            );  
        
    ++server_nonce_counter;
     
    /* Now initialize the global state for keeping information about guests in
     * the chatroom we're currently in, process new guest's included information
     * and fill out their guest descriptor structure in the global array.
     */ 

    /* Reflect the new guest slot in the global guest slots bitmask. */
    roommate_slots_bitmask     |= BITMASK_BIT_ON_AT(next_free_roommate_slot); 
    roommate_key_usage_bitmask |= BITMASK_BIT_ON_AT(next_free_roommate_slot); 

    guest_ix = next_free_roommate_slot;

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
    this_pubkey->free_bits = this_pubkey->size_bits - this_pubkey->used_bits;

    bigint_create(&(roommates[guest_ix].guest_pubkey_mont), MAX_BIGINT_SIZ, 0);  
    Get_Mont_Form(this_pubkey, &(roommates[guest_ix].guest_pubkey_mont), M);
    
    roommates[guest_ix].guest_nonce_counter = 0;
    
    /* Now compute a shared secret with the new guest to get our pair of
     * bidirectional session keys KAB, KBA and the symmetric ChaCha nonce. 
     */
    MONT_POW_modM(
        &(roommates[guest_ix].guest_pubkey_mont)
        ,&own_privkey
        ,M
        ,&temp_shared_secret
    );

    /* Now extract guest_KBA, guest_KAB and guest's symmetric Nonce. */
    memcpy(roommates[guest_ix].guest_KBA, temp_shared_secret.bits, SESSION_KEY_LEN);

    memcpy( 
        roommates[guest_ix].guest_KAB
        ,temp_shared_secret.bits + SESSION_KEY_LEN
        ,SESSION_KEY_LEN
    );

    memcpy( 
        roommates[guest_ix].guest_Nonce
        ,temp_shared_secret.bits + (2 * SESSION_KEY_LEN)
        ,LONG_NONCE_LEN
    );

label_cleanup:
    
    free(one.bits);
    free(aux1.bits);
    free(temp_shared_secret.bits);

    return status;             
}

/* Send a text message to everyone in our chatroom. Construct the payload.
 
 Client ----> Server
 
 Main packet structure:
 
================================================================================
| packetID 30 |  user_ix  |  TXT_LEN   |    AD   |          Signature1         | 
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
u8 construct_msg_30(unsigned char* text_msg, u64 text_msg_len){

    u64 L = num_roommates * (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len);
    u64 payload_len = L + (3 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
    u64 AD_write_offset = 0;
    u64 signed_len = payload_len - SIGNATURE_LEN;

    u8* associated_data = (u8*)calloc(1, L);
    u8* payload = (u8*)calloc(1, payload_len);
    u8  send_K[ONE_TIME_KEY_LEN];
    u8  status = 1;

    u32* chacha_key = NULL;

    FILE* ran_file = NULL;

    bigint guest_nonce_bigint;
    bigint one;
    bigint aux1;

    size_t ret_val;

    memset(send_K, 0, ONE_TIME_KEY_LEN);

    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

    guest_nonce_bigint.bits = 
    (u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    /* Construct the first 3 sections of the payload. */
    *((u64*)(payload + (0 * SMALL_FIELD_LEN))) = PACKET_ID_30; 
    *((u64*)(payload + (1 * SMALL_FIELD_LEN))) = own_ix;
    *((u64*)(payload + (2 * SMALL_FIELD_LEN))) = text_msg_len;

    /* Generate the one-time key K to encrypt the text message with.          */
    /* An encrypted version of key K itself is sent to all receivers.         */
    /* It's encrypted with the pair of symmetric session keys (KAB, KBA)      */
    ran_file = fopen("/dev/urandom", "r");
    
    if(!ran_file){
        printf("[ERR] Client: Couldn't open urandom in msg 30 constructor.\n");
        printf("              Aborting transmission. Telling GUI system.\n\n");
        status = 0;
        goto label_cleanup;
    }
    
    ret_val = fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file);
    
    if(ret_val != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom in msg 30 constructor.\n");
        printf("              Aborting transmission. Telling GUI system.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* Construct the Associated Data within the payload. */
    for(u64 i = 0; i <= MAX_CLIENTS - 2; ++i){
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

            guest_nonce_bigint.free_bits = 
                MAX_BIGINT_SIZ - guest_nonce_bigint.used_bits;

            /* Increment nonce as many times as counter says for this guest. */
            for(u64 j = 0; j < roommates[i].guest_nonce_counter; ++j){
                bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
            }

            AD_write_offset += ONE_TIME_KEY_LEN;

            /* Keep the Nonce with this guest symmetric. */
            bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
            bigint_equate2(&guest_nonce_bigint, &aux1);
            ++(roommates[i].guest_nonce_counter);

            /* Now encrypt and place the text message with K. */
            CHACHA20( 
                text_msg                             /* text - the text msg   */
               ,text_msg_len                         /* text_len in bytes     */
               ,(u32*)(guest_nonce_bigint.bits)      /* Nonce (short)         */
               ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* nonce_len in uint32_ts*/
               ,chacha_key                           /* chacha Key            */
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

    /* Now calculate a cryptographic signature of the whole packet's payload. */
    
    Signature_GENERATE( M, Q, Gm, payload, signed_len
                       ,(payload + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

    /* Ready to send the constructed packet to the Rosetta server now. */

    /* Connect to the Rosetta server. */
    /*
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) ){
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        printf("              ERRNO = %d\n\n", errno);
        perror("connect() failed, errno was set");
        status = 0;
        goto label_cleanup;
    }
*/
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send constructed packet 30.\n");
        printf("              Which is the request to send a text message\n");
        printf("              Tell GUI to tell the user about this!\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Sent a request to send a text message!\n\n");
    }

label_cleanup:

    free(guest_nonce_bigint.bits);
    free(one.bits);
    free(aux1.bits);

    free(associated_data);
    free(payload);

    if(ran_file != NULL) { fclose(ran_file); }

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
u8 process_msg_30(u8* payload, u8* name_with_msg_string, u64* result_chars){

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

    const u64 text_len  = *((u64*)(payload + (2 * SMALL_FIELD_LEN)));
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
    u8  status = 1;

    bigint *recv_e = NULL;
    bigint *recv_s = NULL;
    bigint  guest_nonce_bigint;
    bigint  one;
    bigint  aux1;

    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

    guest_nonce_bigint.bits = 
    (u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    memset(decrypted_key, 0, ONE_TIME_KEY_LEN);
    memset(temp_user_id,  0, SMALL_FIELD_LEN);

    if(text_len < 1 || text_len > MAX_TXT_LEN) {

        printf("[ERR] Client: Text message by a guest is of invalid length.\n");
        printf("              Obtained message length: %lu\n\n", text_len);
        status = 0;
        goto label_cleanup;
    }

    AD_slot_len  = SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_len;
    AD_len       = num_roommates * AD_slot_len;
    sign2_offset = (3 * SMALL_FIELD_LEN) + SIGNATURE_LEN + AD_len;
    sign1_offset = sign2_offset - SIGNATURE_LEN;

    /* Find the index of the guest with this userID. */
    for(u64 i = 0; i <= num_roommates - 2; ++i){
        if( roommate_slots_bitmask & BITMASK_BIT_ON_AT(i) ){
            
            /* if userIDs match. */
            if(strncmp( roommates[i].guest_user_id
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
        status = 0;
        goto label_cleanup;
    }

    /* Validate the authenticity of the server AND the sending client. */
    
    status = authenticate_server(payload, sign2_offset, sign2_offset);    

    if(status != 1){
        printf("[ERR] Client: Invalid server signature in process_msg_30.\n\n");
        status = 0;   
        goto label_cleanup;    
    }  

    /* Now the sender client's signature. */

    /* Reconstruct the sender's signature as the two BigInts that make it up. */
    s_offset = sign1_offset;
    e_offset = (sign1_offset + sizeof(bigint) + PRIVKEY_LEN);    

    recv_s = (bigint*)(payload + s_offset);
    recv_e = (bigint*)(payload + e_offset);  

    recv_s->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    recv_e->bits = (u8*)calloc(1, MAX_BIGINT_SIZ);

    memcpy( recv_s->bits
           ,payload + (sign1_offset + sizeof(bigint))
           ,PRIVKEY_LEN
    );
    
    memcpy( recv_e->bits
           ,payload + (sign1_offset + (2*sizeof(bigint)) + PRIVKEY_LEN)
           ,PRIVKEY_LEN
    );
       
    /* Verify the sender's cryptographic signature. */
    status = Signature_VALIDATE(
                     Gm, &(roommates[sender_ix].guest_pubkey_mont)
                    ,M, Q, recv_s, recv_e
                    ,(payload + sign1_offset), sign1_offset
    ); 

    if(status != 1) {
        printf("[ERR] Client: Invalid sender signature in msg_30 Drop.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* Now that the packet seems legit, find our slot in the associated data. */
    for(u64 i = 0; i < num_roommates; ++i){

        memcpy(temp_user_id, AD_pointer + (i * AD_slot_len), SMALL_FIELD_LEN);

        if(strncmp(temp_user_id, own_user_id, SMALL_FIELD_LEN) == 0){
            our_AD_slot = i;
            break;
        }
    }

    /* If we didn't find our userID in the associated data, drop the message. */
    if(our_AD_slot == (MAX_CLIENTS + 1)) {
        printf("[ERR] Client: Didn't find our message slot in AD. Drop.\n\n");
        status = 0;
        goto label_cleanup;
    }

    /* TODO: Extract encrypted key and msg, decrypt them, send MSG to GUI. */

    /* Extract the encrypted key and message from our slot in associated data */

    /* Decide whether to encrypt with session key KAB or with KBA. */
    if( roommate_key_usage_bitmask & BITMASK_BIT_ON_AT(sender_ix) ){
        chacha_key = (u32*)(roommates[sender_ix].guest_KAB);
    }
    else{
        chacha_key = (u32*)(roommates[sender_ix].guest_KBA);
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

    guest_nonce_bigint.free_bits = 
        MAX_BIGINT_SIZ - guest_nonce_bigint.used_bits;


    /* Increment nonce as many times as counter says for this guest. */
    for(u64 j = 0; j < roommates[sender_ix].guest_nonce_counter; ++j){
        bigint_add_fast(&guest_nonce_bigint, &one, &aux1);
        bigint_equate2(&guest_nonce_bigint, &aux1);     
    }

    our_K_pointer = AD_pointer + (our_AD_slot * AD_slot_len) + SMALL_FIELD_LEN;
    our_msg_pointer = our_K_pointer + ONE_TIME_KEY_LEN;

    /* Place this guest's encrypted one-time ChaCha key. */
    CHACHA20( 
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
    CHACHA20( 
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
    memcpy(name_with_msg_string, payload + SMALL_FIELD_LEN, SMALL_FIELD_LEN);
    memcpy(name_with_msg_string, GUI_string_helper, 2);
    memcpy(name_with_msg_string, decrypted_msg, text_len);

label_cleanup:

    if(recv_s != NULL) { 
        free(recv_s->bits);           
    }

    if(recv_e != NULL) { 
        free(recv_e->bits);           
    }

    free(guest_nonce_bigint.bits);
    free(one.bits);
    free(aux1.bits);
    free(decrypted_msg);

    return status;
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
u8 construct_msg_40(void){

    const u64 payload_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 1;
    u8 payload[payload_len];

    memset(payload, 0, payload_len);

    *((u64*)(payload)) = PACKET_ID_40;
    *((u64*)(payload + SMALL_FIELD_LEN)) = own_ix;

    //memcpy((payload + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    Signature_GENERATE( 
        M, Q, Gm, payload, 2 * SMALL_FIELD_LEN, 
        payload + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    /* Connect to the Rosetta server. */
    /*
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) ){
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        printf("              ERRNO = %d\n\n", errno);
        perror("connect() failed, errno was set");
        status = 0;
        goto label_cleanup;
    }
*/
    /* Transmit our request to the Rosetta server. */
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't poll the server for anything new.\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Polled the server for anything new.\n\n");
    }

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

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_40. Drop.\n\n");
        status = 0;
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
u8 process_msg_50(u8* payload){

    u64 sender_ix = MAX_CLIENTS + 1;
    
    u8 status; 

    /* Verify the server's signature first. */
    status = authenticate_server(payload, 2 * SMALL_FIELD_LEN, 2 * SMALL_FIELD_LEN);

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_50. Drop.\n\n");
        status = 0;
        goto label_cleanup;           
    }

    /* Find the index of the guest with this userID. */
    for(u64 i = 0; i <= num_roommates - 2; ++i){
        if( roommate_slots_bitmask & BITMASK_BIT_ON_AT(i) ){
            
            /* if userID matches the one in payload */
            if(strncmp( roommates[i].guest_user_id
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

    /* If no guest found with the userID in the payload */
    if(sender_ix == MAX_CLIENTS + 1){
        printf("[ERR] Client: No departed guest found in chatroom. Drop.\n\n");
        status = 0;
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
     */
    memset(roommates[sender_ix].guest_user_id, 0, SMALL_FIELD_LEN);
    free(roommates[sender_ix].guest_pubkey.bits);
    free(roommates[sender_ix].guest_pubkey_mont.bits);
    free(roommates[sender_ix].guest_KBA);
    free(roommates[sender_ix].guest_KAB);
    free(roommates[sender_ix].guest_Nonce);

    /* Now zero out the descriptor itself without the risk of memory leaks. */
    memset(&(roommates[sender_ix]), 0, sizeof(struct roommate));

    roommate_slots_bitmask     &= ~(BITMASK_BIT_ON_AT(sender_ix));
    roommate_key_usage_bitmask &= ~(BITMASK_BIT_ON_AT(sender_ix));

    --num_roommates;

    /* Cleanup. */
label_cleanup:

    /* No function cleanup for now. Keep the label for completeness. */

    return status; 
}

/* Tell the Rosetta server that the user wants to leave the chatroom.
 
 Client ----> Server
  
================================================================================
| packet ID 50 |  user_ix  |                    SIGNATURE                      | 
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
u8 construct_msg_50(void){

    const u64 payload_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 1;
    u8 payload[payload_len];

    memset(payload, 0, payload_len);

    for(u64 i = 0; i <= MAX_CLIENTS - 2; ++i){

        /* Make sure we deallocate any memory pointed to by pointers contained
         * in the struct itself or by pointers in an object that's part of the
         * struct BEFORE we zero out the descriptor itself.
         */
        if(roommate_slots_bitmask & BITMASK_BIT_ON_AT(i)){
            memset(roommates[i].guest_user_id, 0, SMALL_FIELD_LEN);
            free(roommates[i].guest_pubkey.bits);
            free(roommates[i].guest_pubkey_mont.bits);
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

    *((u64*)(payload)) = PACKET_ID_50;

    memcpy((payload + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    Signature_GENERATE( 
        M, Q, Gm, payload, 2 * SMALL_FIELD_LEN, 
        payload + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    /* Connect to the Rosetta server. */
    /*
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) ){
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        printf("              ERRNO = %d\n\n", errno);
        perror("connect() failed, errno was set");
        status = 0;
        goto label_cleanup;
    }
*/
    /* Transmit our request to the Rosetta server. */
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send request to leave the room.\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Told the server we wanna leave the room.\n\n");
    }

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
u8 process_msg_51(u8* payload){

    u8 status = 1;

    /* Verify the server's signature first. */
    status = authenticate_server(payload, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status != 1){
        printf("[ERR] Client: Invalid signature in process_msg_51. Drop.\n\n");
        status = 0;
        goto label_cleanup;           
    }

    for(u64 i = 0; i <= MAX_CLIENTS - 2; ++i){

        /* Make sure we deallocate any memory pointed to by pointers contained
         * in the struct itself or by pointers in an object that's part of the
         * struct BEFORE we zero out the descriptor itself.
         */
        if(roommate_slots_bitmask & BITMASK_BIT_ON_AT(i)){
            memset(roommates[i].guest_user_id, 0, SMALL_FIELD_LEN);
            free(roommates[i].guest_pubkey.bits);
            free(roommates[i].guest_pubkey_mont.bits);
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

    /* Cleanup. */
label_cleanup:

    /* No function cleanup for now. Keep the label for completeness. */

    return status; 
}

/* Tell the Rosetta server that the user wants to log off.
 
 Client ----> Server
  
================================================================================
| packet ID 60 |  user_ix  |                    SIGNATURE                      | 
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
u8 construct_msg_60(void){

    const u64 payload_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 1;
    u8 payload[payload_len];

    memset(payload, 0, payload_len);

    *((u64*)(payload)) = PACKET_ID_60;

    memcpy((payload + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    Signature_GENERATE( 
        M, Q, Gm, payload, 2 * SMALL_FIELD_LEN, 
        payload + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    own_ix = 0;

    /* Connect to the Rosetta server. */
    /*
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) ){
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        printf("              ERRNO = %d\n\n", errno);
        perror("connect() failed, errno was set");
        status = 0;
        goto label_cleanup;
    }
*/
    /* Transmit our request to the Rosetta server. */
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send request to get logged off.\n\n");
        status = 0;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Told the server we wanna get logged off.\n\n");
    }

label_cleanup: 

    /* No function cleanup yet. Keep the label for completeness. */

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

        if(ret != 1){
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

            if(ret != 1){
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

    u8 status = 1;
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
        status = 0;
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
        status = 0;
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
        status = 0;
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

u8 login(u8* password, int password_len){

    u8 status;
    u8 msg_buf[MAX_TXT_LEN];

    ssize_t bytes_read;

    status = self_init(password, password_len);

    if(status != 1){
        printf("[ERR] Client: Core initialization failed. Aborting login.\n\n");
        return 0;
    }

    /* Begin the login handshake to transport our long-term public key in a
     * secure and authenticated fashion even without a session shared secret,
     * by using a different, extremely short-term pair of public / private keys
     * and shared secret that get destroyed right after this login handshake.
     */

    /* Contains a send() call. A server reply is then expected. */
    if( (status = construct_msg_00()) != 1){
        printf("[ERR] Client: Sender of msg_00 failed. Aborting login.\n\n");
        return 0;
    }

    printf("[OK]  Client: Sent msg_00 to server.\n\n");

    memset(msg_buf, 0, MAX_TXT_LEN);

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't receive a reply to msg_00.\n\n");
        return 0;
    }

    printf("[OK]  Client: Received reply to msg_00: %lu bytes.\n", bytes_read);

    if(     (*((u64*)msg_buf) != PACKET_ID_02)
        &&  (*((u64*)msg_buf) != PACKET_ID_00) )
    {
        printf("[ERR] Client: Unexpected reply by the server to msg_00\n\n");
        return 0;
    }

    if((*((u64*)msg_buf) == PACKET_ID_00)){

        /* This sends msg_01, then a reply to that is expected. */
        if ((status = process_msg_00(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_00 failed. Abort login.\n\n");
            return 0;
        }

        printf("[OK]  Client: Sent msg_01 to server.\n\n");
    }
    else{
        printf("[OK]  Client: Server told us to try login later.\n\n");

        if ((status = process_msg_02(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_02 failed. Abort login.\n\n");
            return 0;
        }

        status = 3;
    }

    memset(msg_buf, 0, MAX_TXT_LEN);

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't receive a reply to msg_01.\n\n");
        return 0;
    }

    printf("[OK]  Client: Received reply to msg_01: %lu bytes.\n", bytes_read);

    if( *((u64*)msg_buf) == PACKET_ID_01 ){

        printf("[OK]  Client: Rosetta server told us login succeeded!\n\n");

        if ((status = process_msg_01(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_01 failed. Abort login.\n\n");
            return 0;
        }

        status = 2;
    }

    else if( *((u64*)msg_buf) == PACKET_ID_02 ){

        printf("[OK]  Client: Rosetta server told us to try later, full!\n\n");

        if ((status = process_msg_02(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_02 failed. Abort login.\n\n");
            return 0;
        }

        status = 3;
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_01.\n\n");
        status = 0;
    }

    printf("\n\n\n******** LOGIN COMPLETED *********\n\n\n");

    return status;
}

u8 make_new_chatroom(unsigned char* roomid, int roomid_len,
                     unsigned char* userid, int userid_len
                    )
{
    u64 userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64 roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len; 

    u8 status;
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

    /* Capture the server's reply. */

    memset(msg_buf, 0, MAX_TXT_LEN);

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't recv() a reply to msg_10.\n\n");
        perror("errno = ");
        return 0;
    }

    printf("[OK]  Client: Received reply to msg_10: %lu bytes.\n", bytes_read);

    if( *((u64*)msg_buf) == PACKET_ID_10 ){

        printf("[OK]  Client: Rosetta told us our room has been created!\n\n");

        if ((status = process_msg_10(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_10 failed.\n\n");
            return 0;
        }

        status = 2;
    }

    else if( *((u64*)msg_buf) == PACKET_ID_11 ){

        printf("[OK]  Client: Rosetta told us to try later, it's full!\n\n");

        if ((status = process_msg_11(msg_buf)) != 1){
            printf("[ERR] Client: process_msg_11 failed.\n\n");
            return 0;
        }

        return 3;
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_10.\n\n");
        return 0;
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

    return status;
}

u8 join_chatroom(unsigned char* roomid, int roomid_len,
                 unsigned char* userid, int userid_len
                )
{
    u64 userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64 roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len;
    u64 msg_len;

    u8 status;
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
    if(status != 1){
        return 0;
    }

    /* Capture the server's reply. */
    memset(msg_buf, 0, MAX_TXT_LEN);

    printf("Waiting for the server to reply with PACKET_ID = 20.\n");

    bytes_read = recv(own_socket_fd, msg_buf, MAX_TXT_LEN, 0);

    if(bytes_read == -1){
        printf("[ERR] Client: Couldn't recv() a reply to msg_20.\n\n");
        perror("errno = ");
        return 0;
    }

    printf("[OK]  Client: Received reply to msg_20: %lu bytes.\n", bytes_read);

    if( *((u64*)msg_buf) == PACKET_ID_20 ){

        printf("[OK]  Client: Rosetta told us we've now joined the room!\n\n");

        msg_len = bytes_read;

        if ((status = process_msg_20(msg_buf, msg_len)) != 1){
            printf("[ERR] Client: process_msg_20 failed.\n\n");
            return 0;
        }
    }

    else{
        printf("[ERR] Client: Unexpected reply by the server to msg_20.\n\n");
        /* return BAD */
        return 0;
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

    return 1;
}























