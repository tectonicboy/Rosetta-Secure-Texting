/* First thing done when we start the Rosetta server - initialize it. */
u8 self_init()
{
    FILE* privkey_dat = NULL;
    u8 status = 0;

    temp_handshake_buf = NULL;
    status = init_communication();
    if(status){
        printf("[ERR] Server: Communication init function ptr call fail.\n");
        goto label_cleanup;
    }
    /* Allocate memory for the temporary login handshake memory region. */
    temp_handshake_buf = calloc(1, TEMP_BUF_SIZ);

    /*  Server will use its private key to compute cryptographic signatures of
     *  everything it transmits, so all users can authenticate it using the
     *  server's long-term public key they already have at install time.
     */
    privkey_dat = fopen(SERV_PRIVKEY_PATH, "r");
    if(!privkey_dat){
        perror("[ERR] Server: couldn't open private key DAT file:\n");
        status = 1;
	      goto label_cleanup;
    }
    if(fread(server_privkey, 1, PRIVKEY_LEN, privkey_dat) != PRIVKEY_LEN){
        printf("[ERR] Server: couldn't get private key from file. Aborting.\n");
        status = 1;
	      goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Successfully loaded private key.\n");
    }
    /* Initialize the global BigInt that stores the server's private key. */
    bigint_create_from_u32(&server_privkey_bigint, MAX_USED_BITWIDTH, 0);
    memcpy(server_privkey_bigint.bits, server_privkey, PRIVKEY_LEN);
    server_privkey_bigint.used_bits =
      get_used_bits(server_privkey, PRIVKEY_LEN);
    /* Load in other BigInts needed for the cryptography to work.   */
    /* Diffie-Hellman modulus M, large prime number around 3070-bit */
    M = get_bigint_from_dat
          (DH_MODULUS_M_PATH, DH_M_BITWIDTH, MAX_USED_BITWIDTH);
    /* DH prime order Q, dividing M-1, around 320-bit. Gives M security. */
    Q = get_bigint_from_dat
          (DH_PRIME_ORDER_Q_PATH, DH_Q_BITWIDTH, MAX_USED_BITWIDTH);
    /* Diffie-Hellman generator G = [2 ^ ((M-1) / Q)] mod M */
    G = get_bigint_from_dat
          (DH_GENERATOR_G_PATH, DH_G_BITWIDTH, MAX_USED_BITWIDTH);
    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_bigint_from_dat
          (DH_G_MONT_PATH, DH_G_MONT_BITWIDTH, MAX_USED_BITWIDTH);
    /* The public key of the Rosetta server, ~ same bitwidth as M. */
    server_pubkey_bigint = get_bigint_from_dat(SERV_PUBKEY_PATH,
                                               SERV_PUBKEY_BITWIDTH,
                                               MAX_USED_BITWIDTH);
    /* Initialize the mutex that will be used to prevent the main thread and
     * the connection checker thread from getting into a race condition.
     */
    if(pthread_mutex_init(&mutex, NULL) != 0) {
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

label_cleanup:
    if(privkey_dat){
        fclose(privkey_dat);
    }
    free(temp_handshake_buf);
    return status;
}

/*  To make the server design more elegant, this top-level message processor
 *  only checks whether the message is legit or not, and which of the predefined
 *  accepted types it is.
 *
 *  The message is then sent to its own individual processor function to be
 *  further analyzed and reacted to as defined by Rosetta's custom userspace
 *  communication protocol.
 *
 *  This logical split of functionality eases the server implementation.
 *
 *  The complete list of possible legitimate transmissions to the server:
 *
 *      - A client decides to log in Rosetta
 *      - A client decides to make a new chat room
 *      - A client decides to join a chat room.
 *      - A client decides to send a new message to the chatroom.
 *      - A client decides to poll the server about unreceived messages.
 *      - A client decides to exit the chat room they're in.
 *      - A client decides to log off Rosetta.
 */
u8 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u64 sock_ix)
{
    u64 transmission_type = 0;
    u64 found_user_ix = 0;
    u64 text_msg_len;
    s64 expected_siz = 0;
    u32 status = 0;
    char *msg_type_str = calloc(1, 3);

    /* Read the first 8 bytes to see what type of init transmission it is. */
    memcpy(&transmission_type, client_msg_buf, SMALL_FIELD_LEN);

    switch(transmission_type){

    /* A client tried to log in Rosetta */
    case(PACKET_ID_00):{
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN;
        strncpy(msg_type_str, "00\0", 3);
        if(bytes_read != expected_siz){
            status = 200;
            login_not_finished = 0;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        status = (uint32_t)process_msg_00(client_msg_buf, sock_ix);
        if(status){
            login_not_finished = 0;
            status = 200;
        }
        break;
    }
    /* Login part 2 - client sent their encrypted long-term public key. */
    case(PACKET_ID_01):{
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES;
        strncpy(msg_type_str, "01\0", 3);
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        status = (uint32_t)process_msg_01(client_msg_buf, sock_ix);
        if(status){
            status = 200;
        }
        break;
    }
    /* A client wants to create a new chatroom of their own. */
    case(PACKET_ID_10):{
        expected_siz = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + SIGNATURE_LEN;
        strncpy(msg_type_str, "10\0", 3);
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_10(client_msg_buf, sock_ix);
        break;
    }
    /* A client wants to join an existing chatroom. */
    case(PACKET_ID_20):{
        expected_siz = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + SIGNATURE_LEN;
        strncpy(msg_type_str, "20\0", 3);
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_20(client_msg_buf, sock_ix);
        break;
    }
    /* A client wants to send a text message to everyone else in the chatroom */
    case(PACKET_ID_30):{
        strncpy(msg_type_str, "30\0", 3);

        /* Size must be in bytes:
         *
         *   (3 * SMALL_FIELD_LEN) + L + SIG_LEN
         *
         *   where L is the length of associated data:
         *
         *   L = (people in room - 1) * (SMALL_LEN + ONE_TIME_KEY_LEN + TXT_LEN)
         *
         *   where TXT_LEN is given in the 3rd SMALL_FIELD_LEN field.
         */
        for(u64 x = 0; x < MAX_CLIENTS; ++x){
            if(strncmp( clients[x].user_id
                       ,(const char*)(client_msg_buf + SMALL_FIELD_LEN)
                       ,SMALL_FIELD_LEN
                      ) == 0)
            {
                found_user_ix = x;
                break;
            }
        }
        memcpy( &text_msg_len
               ,client_msg_buf + (2 * SMALL_FIELD_LEN)
               ,SMALL_FIELD_LEN
              );
        expected_siz =   (3 * SMALL_FIELD_LEN)
                       + (
                          (rooms[clients[found_user_ix].room_ix].num_people - 1)
                          *
                          (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len)
                         )
                       + SIGNATURE_LEN;

        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_30( client_msg_buf
                       ,expected_siz
                       ,expected_siz - SIGNATURE_LEN
                       ,found_user_ix
                      );
        break;
    }
    /* A client polled the server asking for any pending unreceived messages. */
    case(PACKET_ID_40):{
        strncpy(msg_type_str, "40\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_40(client_msg_buf, sock_ix);
        break;
    }
    /* A client decided to exit the chatroom they're currently in. */
    case(PACKET_ID_50):{
        strncpy(msg_type_str, "50\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_50(client_msg_buf);
        break;
    }
    /* A client decided to log off Rosetta. */
    case(PACKET_ID_60):{
        strncpy(msg_type_str, "60\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_60(client_msg_buf);
        /* Indicate to this client's poll listening thread function to return */
        status = 100;
        break;
    }

    /* Also do something in case it was a bad unrecognized transmission.  */
    default:{
        /* DO NOT REACT TO BAD PACKETS!! Drop them silently instead. */
        break;
    } /* end of default */
    } /* end of switch  */

    goto label_cleanup;

label_error:
    printf("[ERR] Server: MSG Type was %s but of wrong size or contents\n"
           "              or another error occurred, check log.\n\n"
           ,msg_type_str);

    printf("              Size was: %ld\n", bytes_read);
    printf("              Expected: %ld\n", expected_siz);
    printf("\n[OK]  Server: Discarding transmission.\n\n ");

label_cleanup:
    free(msg_type_str);
    return status;
}

void* start_new_client_thread(void* ix_ptr)
{
    u8* client_msg_buf = calloc(1, MAX_MSG_LEN);
    ssize_t bytes_read;
    u32 status;
    u64 ix;

    memcpy(&ix, ix_ptr, sizeof(ix));
    memset(client_msg_buf, 0, MAX_MSG_LEN);

    while(1){
        /* Blocking. TIMES OUT automatically via SO_RCVTIMEO socket option. */
        bytes_read = receive_payload(ix, client_msg_buf, MAX_MSG_LEN);
        if( __builtin_expect (bytes_read <= 0, 0) ){
            if(temp_handshake_memory_region_isLocked == 1){
                /* At various points of this buffer's lifetime, various pointers
                 * in it point to heap memory. Sudden disruption of login
                 * leading to here DOES NOT free() them or erase the memory
                 * they might point to.
                 * TODO ^
                 */
                memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);
                temp_handshake_memory_region_isLocked = 0;
            }
            if(login_not_finished){
                login_not_finished = 0;
                close(client_socket_fd[ix]);
                if(ix < next_free_user_ix) next_free_user_ix = ix;
            }
            else{
                remove_user_from_rosetta(ix);
            }
            break;
        }
        pthread_mutex_lock(&mutex);
        status = identify_new_transmission(client_msg_buf, bytes_read, ix);

        /* 200 - login can not proceed. Remove the user. No struct slot has
         *       been allocated yet, but a socket is used and next_free_user_ix
         *       has been moved. Move it back, release the socket, stop this
         *       thread.
         */
        if(status == 200){
            /* At various points of this buffer's lifetime, various pointers
             * in it point to heap memory. Sudden disruption of login leading to
             * here DOES NOT free() them or erase the memory they point to.
             * TODO ^
             */
            u8 socket_closed = 0;
            if( users_status_bitmask & (1ULL << (63ULL - ix)) ){
                remove_user_from_rosetta(ix);
                socket_closed = 1;
            }
            memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);
            temp_handshake_memory_region_isLocked = 0;
            if(!socket_closed) close(client_socket_fd[ix]);
            if(ix < next_free_user_ix) next_free_user_ix = ix;
            pthread_mutex_unlock(&mutex);
            break;
        }
        if(status != 100 && status > 0){
            printf("[ERR] Server: identifying new transmission went bad!\n");
            remove_user_from_rosetta(ix);
            pthread_mutex_unlock(&mutex);
            break;
        }
        /* In this case, by definition, it's also OK to stop accepting any more
         * poll requests by this client since they know they're not in the room
         * anymore since they initiated their leaving.
         */
        if( status == 100 ) {
            printf("[OK] Server: client poll thread [%lu] exits: "
                   "User logged out!\n"
                   ,ix
                  );
            pthread_mutex_unlock(&mutex);
            break;
        }

        memset(client_msg_buf, 0, bytes_read);
        pthread_mutex_unlock(&mutex);
    }

    free(client_msg_buf);
    return NULL;
}

