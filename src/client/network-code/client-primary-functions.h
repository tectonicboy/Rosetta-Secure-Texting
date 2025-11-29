/******************************************************************************/

#include "../../lib/coreutil.h"
#include "client-communications.h"
#include "client-packet-functions.h"


/* These function pointers tell the client whether to communicate through
 * Unix Domain sockets, or through Internet sockets. If the client was started
 * for the Rosetta Testing Framework, communication with the server (as a 
 * local OS process talking to other OS processes as clients and thus simulating
 * real people texting on the internet without headaches with network issues)
 * is done via locak unix interprocess communications (AF_UNIX sockets). If the
 * client is to be run normally for a real Rosetta user to tune in to chatrooms
 * and text other people, Internet sockets provide the communication mechanism.
 *
 * The two communication mechanisms need different code for (1) initialization,
 * (2) transmitting a message to other people and (3) receiving a message sent
 * by other people (in both cases relayed by the server as an intermediary).
 *
 * The GUI means the clienht was started for the real thing, the Test Framework
 * means it was started as a test user emulated via a local OS process.
 * This in turn sets these
 * function pointers to the actual respective functions that implement the 3
 * differing communication operations. This is at client initialization time.
 *
 * This allows for an elegant way to simplify in-client communication code while
 * maintaining working messaging both for Rosetta Test Framework and for the
 * real thing with only one set of simple, descriptive API functions, instead of
 * polluting client code with sockets API-specific code for AF_UNIX / Internet.
 */
uint8_t(*init_communication)(void);
uint8_t(*transmit_payload)  (uint8_t* buf, size_t send_siz);
uint8_t(*receive_payload)   (uint8_t* buf, uint64_t* recv_len);
void   (*end_communication) (void);

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
u8 self_init(u8* password, int password_len, char* save_dir){

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

    memset(&prms, 0, sizeof(struct Argon2_parms));

    /* Initialize data structures for maintaining global state & bookkeeping. */
    memset(roommates,           0, roommates_arr_siz * sizeof(struct roommate));
    memset(own_privkey_buf,     0, PRIVKEY_LEN);
    memset(temp_handshake_buf,  0, TEMP_BUF_SIZ);

    /* Load user's public key, decrypt and load user's private key. */

    savefile = fopen(save_dir, "r");

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
    blake2b_init(saved_pubkey, PUBKEY_LEN, 0, 64, b2b_pubkey_output);

    /* Now construct the complete Salt parameter with the 2 components. */
    memcpy(Salt, saved_string, ARGON_STRING_LEN);
    memcpy(Salt + ARGON_STRING_LEN, b2b_pubkey_output, 64);

    prms.S = Salt;

    /* Set other parameters to Argon2. */
    prms.len_P = PASSWORD_BUF_SIZ;        /* Length of password (as a key)    */
    prms.len_S = (ARGON_STRING_LEN + 64); /* Length of the Salt parameter     */
    prms.len_K = 0;                       /* unused here, so set length to 0  */
    prms.len_X = 0;                       /* unused here, so set length to 0  */

    Argon2_MAIN(&prms, argon2_output_tag);

    /* Let V be the leftmost 32 (chacha_key_len) bytes of Argon2's output hash.
     * Use V as a key in ChaCha20, along with the saved 16-byte Nonce
     * (from user's save file) to decrypt the user's saved private key.
     */
    memcpy(V, argon2_output_tag, chacha_key_len);

    /* Decrypt the saved private key. */
    chacha20( saved_privkey                       /* text - private key  */
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

    /* Compute a public key with that private key and M, Q, G. If it's the same
     * as the public key stored on the filesystem, the private key was
     * decrypted successfully, with the original correct password.
     */

    save_bigint_to_dat("temp_priv.dat", &own_privkey);

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
    M = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_M.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    if(M == NULL){
        printf("[ERR] Client: Failed to get M from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* 320-bit prime exactly dividing M-1, making M cryptographically strong. */
    Q = get_bigint_from_dat
     ( 320
      ,"../../bin/saved_Q.dat"
      ,320
      ,MAX_BIGINT_SIZ
     );

    if(Q == NULL){
        printf("[ERR] Client: Failed to get Q from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Diffie-Hellman generator G = 2^((M-1)/Q) */
    G = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_G.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    if(G == NULL){
        printf("[ERR] Client: Failed to get G from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_Gm.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    if(Gm == NULL){
        printf("[ERR] Client: Failed to get Gm from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Grab the server's public key. */
    server_pubkey = get_bigint_from_dat
     ( 3072
      ,"../../bin/server_pubkey.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    if(server_pubkey == NULL){
        printf("[ERR] Client: Failed to get server pubkey from DAT file.\n\n");
        status = 1;
        goto label_cleanup;
    }

    /* Initialize the shared secret with the server. */
    bigint_create(&server_pubkey_mont,   MAX_BIGINT_SIZ, 0);
    bigint_create(&server_shared_secret, MAX_BIGINT_SIZ, 0);

    get_mont_form(server_pubkey, &server_pubkey_mont, M);

    mont_pow_mod_m(&server_pubkey_mont, &own_privkey, M, &server_shared_secret);

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
    server_nonce_bigint.bits =
    (u8*)calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    memcpy( server_nonce_bigint.bits
           ,server_shared_secret.bits + (2 * SESSION_KEY_LEN)
           ,LONG_NONCE_LEN
          );

    server_nonce_bigint.used_bits = get_used_bits
                                     (server_nonce_bigint.bits, LONG_NONCE_LEN);

    server_nonce_bigint.size_bits = MAX_BIGINT_SIZ;

    server_nonce_bigint.free_bits = 
                                 MAX_BIGINT_SIZ - server_nonce_bigint.used_bits;

    /* Initialize the mutex that will be used to prevent the main thread and
     * the poller thread from writing/reading the same data in parallel.
     */
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    status = init_communication();

    pthread_mutex_init(&poll_mutex, NULL);

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

void* begin_polling(__attribute__((unused)) void* input)
{
    u8  text_message_line[MESSAGE_LINE_LEN];
    u8  reply_buf[MAX_TXT_LEN];
    u8* msg_buf;
    u8  status;
    u8  flag_no_poll_reply = 0;

    u64* reply_type_ptr = (u64*)reply_buf;
    u64  curr_msg_type = 0;
    u64  pending_messages = 0;
    u64  read_ix = 0;
    u64  block_len;
    u64  obtained_text_message_line_len = 0;
    u64  curr_msg_len;
    u64  msg_len;
    u64  reply_len;

    status = construct_msg_40(&msg_buf, &msg_len);

    if(status){
        printf("[ERR] Client: (CRIT) Constructing poll packet_40 failed!\n");
        exit(1);
    }

    for(;;){

        flag_no_poll_reply = 0;

        memset(reply_buf, 0, MAX_TXT_LEN);

        usleep(POLL_INTERVAL_MICROS);

        status = transmit_payload(msg_buf, msg_len);
        
        if(status){
            printf("[ERR] Client: Sending poll packet_40 to server failed.\n");
            continue;
        }

        status = receive_payload(reply_buf, &reply_len);

        if(status == 2){
            printf("[ERR] Client: Poll thread: Server reply took too long.\n");
            pthread_kill(main_thread_id, SIGUSR1);
            goto thread_cleanup;
        }
        if(status == 1){
            printf("[ERR] Client: Poll thread: receive_payload() failed.\n");
            pthread_kill(main_thread_id, SIGUSR1);
            goto thread_cleanup;
        }

        u64* aux_ptr64_replybuf;

        /* Call the appropriate function depending on server's response. */

        /* NEW: Handle here replies for join_room and create_room commands. */
        
    if( *reply_type_ptr == PACKET_ID_10 ){
        
        status = process_msg_10(reply_buf);
        
        if (status){
            printf("[ERR] Client: process_msg_10 failed.\n\n");
            pthread_kill(main_thread_id, SIGUSR1);                               
            goto thread_cleanup;
        }
        printf("[OK]  Client: Rosetta told us our room has been created!\n\n");

        flag_no_poll_reply = 1;
    }

    else if( *reply_type_ptr == PACKET_ID_11 ){

        status = process_msg_11(reply_buf);

        if (status){
            printf("[ERR] Client: process_msg_11 failed.\n\n");
            pthread_kill(main_thread_id, SIGUSR1);                               
            goto thread_cleanup;
        }

        printf("[OK]  Client: Rosetta told us: try later, room is full!\n\n");

        flag_no_poll_reply = 1;
    }

    else if(*reply_type_ptr == PACKET_ID_20){

        status = process_msg_20(reply_buf, reply_len);

        if (status){
            printf("[ERR] Client: process_msg_20 failed.\n\n");
            pthread_kill(main_thread_id, SIGUSR1);                               
            goto thread_cleanup;
        }

        printf("\n\n******** ROOM JOINED SUCCESSFULLY *********\n\n\n");           
                                                                                 
        /* ALSO, here is one of 2 possible places where GUI renders the graphics     
         * for the messages sub-window and "exit room" button. GUI code will         
         * do that if it sees returned 0 from here.                                  
         */ 

        flag_no_poll_reply = 1;
    }
 
        /**********************************************************************/

        if( __builtin_expect (flag_no_poll_reply == 1, 0) ){
            
            memset(reply_buf, 0, MAX_TXT_LEN); 
        
            /* A reply to an asynchronously sent user command, eg. join_room,
             * transmitted by the user input thread, was received, so we need to
             * do another recv() to finish this loop cycle's poll request now.
             */
            status = receive_payload(reply_buf, &reply_len);                         
                                                                                 
            if(status == 2){                                                         
                printf("[ERR] Client: Poll thread: Server reply took too long.\n");  
                pthread_kill(main_thread_id, SIGUSR1);                               
                goto thread_cleanup;                                                 
            }                                                                        
            else if(status == 1){                                                         
                printf("[ERR] Client: Poll thread: receive_payload() failed.\n");    
                pthread_kill(main_thread_id, SIGUSR1);                               
                goto thread_cleanup;                                                 
            }  
        }
        
        if( *reply_type_ptr == PACKET_ID_40 ){

            status = process_msg_40(reply_buf);

            if(status){
                printf("[ERR] Client: Packet_40_Reply auth failed!\n");
                pthread_kill(main_thread_id, SIGUSR1);                               
                goto thread_cleanup;
            }
            //printf("[OK]  Client: Server said nothing new after polling.\n\n");
        }
/*

 Server ----> Client

================================================================================
| packetID 41 |     T     |    L_1    | MSG1 |...|    L_T    | MSG_T|  Signat  |
|=============|===========|===========|======|===|===========|======|==========|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN | L_1  |...| SMALL_LEN |  L_T | SIG_LEN  |
--------------------------------------------------------------------------------

*/
        if ( *reply_type_ptr == PACKET_ID_41 ) {           
            aux_ptr64_replybuf = (u64*)(reply_buf + SMALL_FIELD_LEN);
            pending_messages = *aux_ptr64_replybuf;

            read_ix = 2 * SMALL_FIELD_LEN;

            /* At end, read_ix = how many bytes a signature was computed on. */
            for(u64 i = 0; i < pending_messages; ++i){
                aux_ptr64_replybuf = (u64*)(reply_buf + read_ix);
                block_len = *aux_ptr64_replybuf;
                read_ix += block_len + SMALL_FIELD_LEN;
            }

            /* Verify the cryptographic signature now. */
            status = authenticate_server(reply_buf, read_ix, read_ix);

            if(status == 1){
                printf("[ERR] Client: Bad signature in polling reply.\n\n");
                pthread_kill(main_thread_id, SIGUSR1);                               
                goto thread_cleanup;
            }

            /* Start at first message contents. */
            read_ix = 3 * SMALL_FIELD_LEN;

            /* Valid pending message types: 50, 51, 21, 30 */

            /* packet_ID and signature are valid - process each pending MSG.  */
            for(u64 i = 0; i < pending_messages; ++i){
                
                aux_ptr64_replybuf = (u64*)(reply_buf + read_ix);
                curr_msg_type = *aux_ptr64_replybuf;
                
                aux_ptr64_replybuf =(u64*)(reply_buf +read_ix -SMALL_FIELD_LEN);
                curr_msg_len = *aux_ptr64_replybuf;

                if(curr_msg_type == PACKET_ID_50){
                    process_msg_50(reply_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_51){
                    process_msg_51(reply_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_21){
                    process_msg_21(reply_buf + read_ix);
                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
                else if(curr_msg_type == PACKET_ID_30){
                    process_msg_30( reply_buf + read_ix
                                   ,text_message_line
                                   ,&obtained_text_message_line_len
                                  );

                    /* Tell GUI to display the message with obtained length. */
                    printf("\n%s\n", text_message_line);

                    read_ix += SMALL_FIELD_LEN + curr_msg_len;
                    continue;
                }
            }
        }    
    }

thread_cleanup:

    memset(msg_buf,           0x00, msg_len);
    memset(reply_buf,         0x00, MAX_TXT_LEN);
    memset(text_message_line, 0x00, MESSAGE_LINE_LEN);
    pending_messages = 0;
    msg_len          = 0;
    reply_len        = 0;
    read_ix          = 0;
    curr_msg_len     = 0;
    curr_msg_type    = 0;
    free(msg_buf);
    pthread_mutex_unlock(&poll_mutex);

    return NULL;
}

void handle_signal_sigusr1(__attribute__((unused)) int sig)
{
    write(
     STDOUT_FILENO
    ,"[DEBUG] Client: main got a signal by poll thread! Stop scanf.\n"
    ,strlen("[DEBUG] Client: main got a signal by poll thread! Stop scanf.\n\0")
    );

    return;
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

u8 reg(u8* password, int password_len, char* save_dir){

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

    /* Registration step 1: Generate a long-term private/public keys a/A. */

    /* a = random in the range [1, Q) */
    gen_priv_key(PRIVKEY_LEN, privkey_buf);

    /* Interface generating a pub_key still needs priv_key in a file. TODO.  */
    /* Putting it in a file needs it in the form of bigint object. Make one. */
    memcpy(temp_privkey.bits, privkey_buf, PRIVKEY_LEN);
    temp_privkey.size_bits = MAX_BIGINT_SIZ;
    temp_privkey.used_bits = get_used_bits(privkey_buf, PRIVKEY_LEN);
    temp_privkey.free_bits = MAX_BIGINT_SIZ - temp_privkey.used_bits;

    save_bigint_to_dat("temp_privkey.dat", &temp_privkey);

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
    blake2b_init(A_longterm->bits, PUBKEY_LEN, 0, 64, b2b_pubkey_output);

    /* Now construct the complete Salt parameter with the two components. */
    memcpy(Salt,     argon2_salt_string,  ARGON_STRING_LEN);
    memcpy(Salt + ARGON_STRING_LEN, b2b_pubkey_output,  64);

    prms.S = Salt;

    prms.len_P = PASSWORD_BUF_SIZ;
    prms.len_S = (8 + 64);  /* 8-byte string plus 64-byte output of blake2b. */
    prms.len_K = 0;         /* unused here, so set length to 0               */
    prms.len_X = 0;         /* unused here, so set length to 0               */

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

    chacha20( temp_privkey.bits                  /* text - private key  */
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

    user_save = fopen(save_dir, "w");

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

u8 login(u8* password, int password_len, char* save_dir){

    u8   status = 0;
    u8*  msg_buf = NULL;
    u8   reply_buf[MAX_TXT_LEN];

    u64*    reply_type_ptr = (uint64_t*)reply_buf;
    u64     msg_len;
    ssize_t reply_len;


    status = self_init(password, password_len, save_dir);

    if(status){
        printf("[ERR] Client: Core initialization failed. Aborting login.\n\n");
        goto label_cleanup;
    }

    /* Begin the login handshake to transport our long-term public key in a
     * secure and authenticated fashion even without a session shared secret,
     * by using a different, extremely short-term pair of public / private keys
     * and shared secret that get destroyed right after this login handshake.
     */

    status = construct_msg_00(&msg_buf, &msg_len);

    if(status){
        printf("[ERR] Client: Couldn't construct MSG_00 for Login. Abort.\n");
        goto label_cleanup;
    }

    status = transmit_payload(msg_buf, msg_len);

    if(status){
        printf("[ERR] Client: Couldn't send MSG_00 for Login. Abort.\n");
        goto label_cleanup;
    }

    status = receive_payload(reply_buf, (uint64_t*)&reply_len);

    if(status){
        printf("[ERR] Client: Couldn't receive MSG_00 reply by server.\n\n");
        goto label_cleanup;
    }

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

        status = process_msg_00(reply_buf, &msg_buf, &msg_len);

        if(status){
            printf("[ERR] Client: process_msg_00 failed. Abort login.\n\n");
            goto label_cleanup;
        }


/*  Now send the reply back to the Rosetta server:

================================================================================
|  packet ID 01   | Client's encrypted long-term PubKey |  HMAC authenticator  |
|=================|=====================================|======================|
| SMALL_FIELD_LEN |             PUBKEY_LEN              |   HMAC_TRUNC_BYTES   |
--------------------------------------------------------------------------------

*/
        status = transmit_payload(msg_buf, msg_len);

        if(status){
            printf("[ERR] Client: Sending MSG_01 failed.");
            goto label_cleanup;
        }
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

    status = receive_payload(reply_buf, (uint64_t*)&reply_len);

    if(status){
        printf("[ERR] Client: Couldn't receive a reply to msg_01.\n\n");
        goto label_cleanup;
    }

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

    texting_should_stop = 0;
   
    start_polling_thread();

    printf("\n\n\n******** LOGIN COMPLETED *********\n\n\n");

label_cleanup:

    free(msg_buf);

    return status;
}

u8 make_new_chatroom(unsigned char* roomid, int roomid_len,
                     unsigned char* userid, int userid_len
                    )
{
    u64 userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64 roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len;
    u64 msg_len;

    u8  status = 0;
    u8* msg_buf = NULL;

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
    status = construct_msg_10(userid, roomid, &msg_buf, &msg_len);

    if(status){
        printf("[ERR] Client: Couldn't construct msg_10\n\n");
	goto label_cleanup;
    }

/******************************************************************************/

    status = transmit_payload(msg_buf, msg_len);

    if(status){
        printf("\n[ERR] Client: Couldn't send MSG_10 (make_room). Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Sent MSG_10 (make_room) to the Rosetta server.\n");



label_cleanup:
   
    free(msg_buf);
    
    return status;
}

u8 join_chatroom(unsigned char* roomid, int roomid_len,
                 unsigned char* userid, int userid_len
                )
{
    u8  status = 0;
    u8* msg_buf = NULL;

    u64  userid_bytes_for_zeroing = SMALL_FIELD_LEN - userid_len;
    u64  roomid_bytes_for_zeroing = SMALL_FIELD_LEN - roomid_len;
    u64  msg_len;

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
    status = construct_msg_20(userid, roomid, &msg_buf, &msg_len);

    /* bad msg_20 construction. abort. */
    if(status){
        printf("[ERR] Client: Could not construct msg_20 to join a room!\n\n");
        goto label_cleanup;
    }

/******************************************************************************/

    status = transmit_payload(msg_buf, msg_len);

    if(status){
        printf("\n[ERR] Client: Couldn't send MSG_20 (make_room). Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Sent MSG_20 (join_room) to Rosetta server.\n");


label_cleanup:

    free(msg_buf);

    return status;
}

uint8_t send_text(unsigned char* text, uint64_t text_len){

    u64 msg_len;
    u8  status = 0;
    u8* msg_buf = NULL;

    /**************************************************************************/

    status = construct_msg_30(text, text_len, &msg_buf, &msg_len);

    if(status){
        printf("[ERR] Client: Could not construct msg_30 to send a text!\n\n");
        goto label_cleanup;
    }

    status = transmit_payload(msg_buf, msg_len);

    printf("[DEBUG] Client: in send_text(), transmit_payload done!\n");

    if(status){
        printf("\n[ERR] Client: Couldn't send MSG_30 (send_text). Abort.\n");
        goto label_cleanup;
    }

    /* There is no server reply here. Our own text msg will be sent to us
     * by the server and detected by the polling thread, just like the
     * others will detect our new message.
     */

    /**************************************************************************/

label_cleanup:

    free(msg_buf);

    return status;
}

u8 leave_chatroom(void){

    u64 msg_len;

    u8  status = 0;
    u8* msg_buf = NULL;

    /**************************************************************************/
    
    status = construct_msg_50(&msg_buf, &msg_len);
    
    if(status){
        printf("[ERR] Client: Could not construct msg_50 (exit_room).\n\n");
        goto label_cleanup;
    }
    
    status = transmit_payload(msg_buf, msg_len);

    if(status){
        printf("[ERR] Client: Couldn't send MSG_50 (exit_room). Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Sent MSG_50 (exit_room) to Rosetta server.\n");

    /* No server reply here. */

    /**************************************************************************/

label_cleanup:

    free(msg_buf);

    return status;
}

u8 logout(void){
    
    u64 msg_len;

    u8  status = 0;
    u8* msg_buf = NULL;

    /**************************************************************************/
    
    status = construct_msg_60(&msg_buf, &msg_len);

    if(status){
        printf("[ERR] Client: Could not construct msg_60 (logoff).\n\n");
        goto label_cleanup;
    }

    status = transmit_payload(msg_buf, msg_len);

    if(status){
        printf("[ERR] Client: Couldn't send MSG_60 (logoff). Abort.\n");
        goto label_cleanup;
    }
    printf("[OK]  Client: Sent MSG_60 (logoff) to Rosetta server.\n");

    /* No server reply here. */

    end_communication();

    /**************************************************************************/

label_cleanup:

    free(msg_buf);

    return status;
}
