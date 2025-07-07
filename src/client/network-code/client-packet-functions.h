/* A user requested to be logged in Rosetta:

    Client ----> Server

================================================================================
|        PACKET_ID_00         |   Client's short-term public key in the clear  |
|=============================|================================================|
|       SMALL_FIELD_LEN       |                    PUBKEY_LEN                  |
--------------------------------------------------------------------------------

*/
u8 construct_msg_00(u8* msg_buf, u64* msg_len){

    bigint* A_s;
    bigint temp_privkey;

    u8 status = 0;

    *msg_len = SMALL_FIELD_LEN + PUBKEY_LEN;

    msg_buf = calloc(1, *msg_len);

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
    temp_privkey.free_bits = MAX_BIGINT_SIZ - temp_privkey.used_bits;

    memset(temp_handshake_buf, 0, PRIVKEY_LEN);

    memcpy(temp_handshake_buf, &temp_privkey, sizeof(bigint));


    /* Interface generating a pub_key still needs priv_key in a file. TODO. */
    save_bigint_to_dat("temp_privkey_DAT.dat", &temp_privkey);

    A_s = gen_pub_key(PRIVKEY_LEN, "temp_privkey_DAT.dat", MAX_BIGINT_SIZ);

    /* Place our short-term pub_key also in the locked memory region. */
    memcpy(temp_handshake_buf + sizeof(bigint), A_s, sizeof(bigint));

    handshake_memory_region_state = 1;

    /* Construct and send the MSG buffer to the TCP server. */

    *((u64*)(msg_buf)) = PACKET_ID_00;

    memcpy(msg_buf + SMALL_FIELD_LEN, A_s->bits, PUBKEY_LEN);

    printf("[OK]  Client: MSG_00 constructed: %lu bytes\n", *msg_len);

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
u8 process_msg_00(u8* received_buf, u8* msg_01_buf, u64* msg_01_len){

    u64 handshake_buf_key_offset;
    u64 handshake_buf_nonce_offset;
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

    free(msg_01_buf);
    msg_01_buf = calloc(1, *msg_01_len);

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
     *       Y_s   = X_s[64 .. 95 ]
     *       N_s   = X_s[96 .. 107]  <--- 12-byte Nonce for ChaCha20.
     */

    bigint_create(&X_s,  MAX_BIGINT_SIZ, 0);
    bigint_create(&zero, MAX_BIGINT_SIZ, 0);
    bigint_create(&B_sM, MAX_BIGINT_SIZ, 0);

    get_mont_form(&B_s, &B_sM, M);

    /* Check the other side's public key for security flaws and consistency. */
    if(   ((bigint_compare2(&zero, &B_s)) != 3)
        ||
          ((bigint_compare2(M, &B_s)) != 1)
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

    *((u64*)(msg_01_buf)) = PACKET_ID_01;

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
             ,msg_01_buf + SMALL_FIELD_LEN
            );

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

    /* Step 4 of HMAC construction */
    for(u64 i = 0; i < B; ++i){
        K0_XOR_ipad[i] = (K0[i] ^ ipad[i]);
    }

    /* step 5 of HMAC construction */
    memcpy(K0_XOR_ipad_TEXT, K0_XOR_ipad, B);
    memcpy(K0_XOR_ipad_TEXT + B, msg_01_buf + SMALL_FIELD_LEN, PUBKEY_LEN);

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

    memcpy(msg_01_buf + HMAC_reply_offset, BLAKE2B_output, HMAC_TRUNC_BYTES);

    /* The buffer for the reply to the server is now fully constructed! */

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

    u8 status = 0;

    /* Validate the incoming signature with the server's long-term public key
     * on packet_ID_01 (for now... later it will be of the whole payload).
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
		    ,uint8_t*       msg_buf
		    ,uint64_t*      msg_len
		    )
{
    bigint one;
    bigint aux1;

    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    
    FILE* ran_file = NULL;

    u8 status = 0;
    
    u8 send_K[ONE_TIME_KEY_LEN];
    u8 roomID_userID[2 * SMALL_FIELD_LEN];

    *msg_len = signed_len + SIGNATURE_LEN;
    msg_buf  = calloc(1, *msg_len);

    memset(send_K,        0, ONE_TIME_KEY_LEN);
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
        status = 1;
        goto label_cleanup;
    }

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_10 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Increment nonce as many times as the saved counter says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);
    }

    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */

    chacha20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,msg_buf + (2 * SMALL_FIELD_LEN)     /* output target buffer    */
            );

    /* Maintain nonce's symmetry on both server and client with counters. */
    ++server_nonce_counter;

    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);

    /* Prepare the buffer containing the user_ID and room_ID for encryption. */
    memcpy(roomID_userID, requested_roomid, SMALL_FIELD_LEN);
    memcpy(roomID_userID + SMALL_FIELD_LEN, requested_userid, SMALL_FIELD_LEN);

    /* Encrypt the user's requested user_ID and room_ID for their new room. */

    chacha20( roomID_userID                        /* text: one-time key K    */
             ,(2 * SMALL_FIELD_LEN)                /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,msg_buf + sendbuf_roomID_offset     /* output target buffer    */
            );

    ++server_nonce_counter;

    /* Construct the first 2 parts of this packet - identifier and user_ix. */

    *((u64*)(msg_buf)) = PACKET_ID_10;

    *((u64*)(msg_buf + SMALL_FIELD_LEN)) = own_ix;

    /* Now calculate a cryptographic signature of the whole packet's payload. */

    printf("[DEBUG] Client: Calling signature_generate with:\n");

    printf("[DEBUG] Server: signed things of length %lu:\n", signed_len);

    for(u64 i = 0; i < signed_len; ++i){
        printf("%03u ", *(msg_buf + i) );
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("Also, client's real long-term public key:\n");
    bigint_print_info(&own_pubkey);
    bigint_print_bits(&own_pubkey);

    signature_generate( M, Q, Gm, msg_buf, signed_len
                       ,(msg_buf + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

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
                    ,unsigned char* requested_roomid )
{
    bigint one;
    bigint aux1;

    const u64 sendbuf_roomID_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 signed_len            = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    const u64 send_len              = signed_len + SIGNATURE_LEN;

    FILE* ran_file = NULL;

    u8 status = 0;
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
        status = 1;
        goto label_cleanup;
    }

    if( (fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file)) != ONE_TIME_KEY_LEN){
        printf("[ERR] Client: Couldn't read urandom. Abort msg_20 creation.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Increment nonce as many times as the saved counter says. */
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);
    }

    /* Encrypt the one-time key which itself encrypts the room_ID and user_ID */

    chacha20( send_K                               /* text: one-time key K    */
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

    chacha20( roomID_userID                        /* text: one-time key K    */
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

    signature_generate( M, Q, Gm, send_buf, signed_len
                       ,(send_buf + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

    /* Ready to send the constructed packet to the Rosetta server now. */

    if(send(own_socket_fd, send_buf, send_len, 0) == -1){
        printf("[ERR] Client: Couldn't send constructed packet 20.\n");
        printf("              Which is the request to join an existing room\n");
        printf("              Tell GUI to tell the user about this!\n\n");
        status = 1;
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

    u8  status = 0;
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
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);
    }


    chacha20( (msg + SMALL_FIELD_LEN)              /* text: one-time key K    */
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

    chacha20( (msg + recv_type20_AD_offset)        /* text: one-time key K    */
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

    bigint_create(&temp_shared_secret, MAX_BIGINT_SIZ, 0);
    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

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
    for(u64 i = 0; i < server_nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);
    }

    /* DECRYPTING the one time key KC back into K.                            */
    chacha20( (msg + SMALL_FIELD_LEN)              /* text: one-time key KC   */
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
    chacha20( (msg + new_guest_info_offset)        /* text: one-time key K    */
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

    return;
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
    u8  status = 0;

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
            chacha20(
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

    signature_generate( M, Q, Gm, payload, signed_len
                       ,(payload + signed_len)
                       ,&own_privkey, PRIVKEY_LEN
                      );

    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send constructed packet 30.\n");
        printf("              Which is the request to send a text message\n");
        printf("              Tell GUI to tell the user about this!\n\n");
        status = 1;
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
    u8  status = 0;

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
        goto label_cleanup;
    }

    /* Validate the authenticity of the server AND the sending client. */

    status = authenticate_server(payload, sign2_offset, sign2_offset);

    if(status){
        printf("[ERR] Client: Invalid server signature in process_msg_30.\n\n");
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
    status = signature_validate(
                     Gm, &(roommates[sender_ix].guest_pubkey_mont)
                    ,M, Q, recv_s, recv_e
                    ,(payload + sign1_offset), sign1_offset
    );

    if(status) {
        printf("[ERR] Client: Invalid sender signature in msg_30 Drop.\n\n");
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
u8 construct_msg_40(u8* msg_buf, u64* msg_len){

    *msg_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 0;
    
    msg_buf = calloc(1, *msg_len); 

    *((u64*)(msg_buf)) = PACKET_ID_40;
    *((u64*)(msg_buf + SMALL_FIELD_LEN)) = own_ix;

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    signature_generate(
        M, Q, Gm, msg_buf, 2 * SMALL_FIELD_LEN,
        msg_buf + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
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
void process_msg_40(u8* payload){

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

    return;
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
u8 construct_msg_50(void){

    const u64 payload_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 0;
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
    signature_generate(
        M, Q, Gm, payload, 2 * SMALL_FIELD_LEN,
        payload + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    /* Transmit our request to the Rosetta server. */
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send request to leave the room.\n\n");
        status = 1;
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
void process_msg_51(u8* payload){

    u8 status = 0;

    /* Verify the server's signature first. */
    status = authenticate_server(payload, SMALL_FIELD_LEN, SMALL_FIELD_LEN);

    if(status){
        printf("[ERR] Client: Invalid signature in process_msg_51. Drop.\n\n");
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
u8 construct_msg_60(void){

    const u64 payload_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;

    u8 status = 0;
    u8 payload[payload_len];

    memset(payload, 0, payload_len);

    *((u64*)(payload)) = PACKET_ID_60;

    memcpy((payload + SMALL_FIELD_LEN), &own_ix, SMALL_FIELD_LEN);

    /* Compute a cryptographic signature so Rosetta server authenticates us. */
    signature_generate(
        M, Q, Gm, payload, 2 * SMALL_FIELD_LEN,
        payload + (2 * SMALL_FIELD_LEN), &own_privkey, PRIVKEY_LEN
    );

    own_ix = 0;

    /* Transmit our request to the Rosetta server. */
    if(send(own_socket_fd, payload, payload_len, 0) == -1){
        printf("[ERR] Client: Couldn't send request to get logged off.\n\n");
        status = 1;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Told the server we wanna get logged off.\n\n");
    }

label_cleanup:

    /* No function cleanup yet. Keep the label for completeness. */

    return status;
}
