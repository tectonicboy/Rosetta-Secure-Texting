#include <stdint.h>                                                              
#include <stddef.h>                                                              
#include <sys/types.h> 

/* These function pointers tell the server whether to communicate through
 * Unix Domain sockets, or through Internet sockets. If the server was started
 * for the Rosetta Testing Framework, communication with test clients, which are
 * local OS processes talking to each other, simulating real people texting,
 * is done via locak unix interprocess communications (AF_UNIX sockets). If the
 * server is to be run normally for real Rosetta users to tune in to chatrooms
 * and text each other, Internet sockets provide the communication mechanism.
 *
 * The two communication mechanisms need different code for (1) initialization,
 * (2) transmitting a message to a known client, (3) receiving a message sent by
 * a known client and (4) accepting a newly arrived user/test messaging client.
 *
 * A command-line argument determines whether the server was started for the
 * testing framework or for the real system, and this in turn sets these
 * function pointers to the actual respective functions that implement the 4
 * differing communication operations. This is at server initialization time.
 *
 * This allows for an elegant way to simplify in-server communication code while
 * maintaining working messaging both for Rosetta Test Framework and for the
 * real thing with only one set of simple, descriptive API functions, instead of
 * polluting server code with sockets API-specific code for AF_UNIX / Internet.
 */
uint8_t(*init_communication)(void);
uint8_t(*transmit_payload)  (uint64_t socket_ix, uint8_t* buf, size_t send_siz);
ssize_t(*receive_payload)   (uint64_t socket_ix, uint8_t* buf, size_t max_siz);
uint8_t(*onboard_new_client)(uint64_t socket_ix);

#include "../lib/coreutil.h"
#include "server-communications.h"
#include "server-packet-functions.h"

/* First thing done when we start the Rosetta server - initialize it. */
u8 self_init(){

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
   privkey_dat = fopen( "../../bin/server_privkey.dat", "r");
    
    if(!privkey_dat){
        printf("[ERR] Server: couldn't open private key DAT file. Aborting.\n");
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
    bigint_create(&server_privkey_bigint, MAX_BIGINT_SIZ, 0);
    
    memcpy(server_privkey_bigint.bits, server_privkey, PRIVKEY_LEN); 
    
    server_privkey_bigint.used_bits = 
                            get_used_bits(server_privkey, PRIVKEY_LEN);
                            
    server_privkey_bigint.free_bits = 
                            MAX_BIGINT_SIZ - server_privkey_bigint.used_bits;
            
    /* Load in other BigInts needed for the cryptography to work. */
    
    /* Diffie-Hellman modulus M, 3071-bit prime number */                        
    M = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_M.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
    
    /* 320-bit prime exactly dividing M-1, making M cryptographycally strong. */
    Q = get_bigint_from_dat
     ( 320
      ,"../../bin/saved_Q.dat"
      ,320
      ,MAX_BIGINT_SIZ
     );
    
    /* Diffie-Hellman generator G = G = 2^((M-1)/Q) */
    G = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_G.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_bigint_from_dat
     ( 3072
      ,"../../bin/saved_Gm.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
    
    server_pubkey_bigint = get_bigint_from_dat
     ( 3072
      ,"../../bin/server_pubkey.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
    
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



/******************************************************************************/


/******************************************************************************/

/*  To make the server design more elegant, this top-level message processor 
 *  only checks whether the message is legit or not, and which of the predefined
 *  accepted types it is.
 *
 *  The message is then sent to its own individual processor function to be
 *  further analyzed and reacted to as defined by the Security Scheme.
 *
 *  This logical split of functionality eases the server implementation.
 *
 *  Here is a complete list of possible legitimate transmissions to the server:
 *
 *      - A client decides to log in Rosetta
 *      - A client decides to make a new chat room
 *      - A client decides to join a chat room.
 *      - A client decides to send a new message to the chatroom.
 *      - A client decides to poll the server about unreceived messages.
 *      - A client decides to exit the chat room they're in.
 *      - A client decides to log off Rosetta.
 */
u8 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u64 sock_ix){

    u64 transmission_type = 0;
    u64 found_user_ix = 0;
    u64 text_msg_len;

    s64 expected_siz = 0;

    u32 status = 0;

    char *msg_type_str = calloc(1, 3);
   
    /*
    printf("[OK]  Server: Inside packet identifier for socket[%lu]\n", sock_ix);
    */
    
    /* Read the first 8 bytes to see what type of init transmission it is. */
    memcpy(&transmission_type, client_msg_buf, SMALL_FIELD_LEN);
    
    switch(transmission_type){
    
    /* A client tried to log in Rosetta */
    case(PACKET_ID_00):{
        printf("[OK]  Server: Found a matching packet_ID = 00\n\n");
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN;
        
        strncpy(msg_type_str, "00\0", 3);
        
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        
        /* If transmission is of a valid type and size, process it. */
        process_msg_00(client_msg_buf, sock_ix);
        
        break;
    }
    
    /* Login part 2 - client sent their encrypted long-term public key. */
    case(PACKET_ID_01):{  
        printf("[OK]  Server: Found a matching packet_ID = 01\n\n");
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES;
        
        strncpy(msg_type_str, "01\0", 3); 
        
        if(bytes_read != expected_siz){           
            status = 1;
            goto label_error;
        }
    
        /* If transmission is of a valid type and size, process it. */
        process_msg_01(client_msg_buf, sock_ix); 
        
        break;           
    }
    
    /* A client wants to create a new chatroom of their own. */
    case(PACKET_ID_10):{
        printf("[OK]  Server: Found a matching packet_ID = 10\n\n");
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
        printf("[OK]  Server: Found a matching packet_ID = 20\n\n");
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
        printf("[OK]  Server: Found a matching packet_ID = 30\n\n");
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
         
        /*
        memcpy( &found_user_ix
               ,client_msg_buf + SMALL_FIELD_LEN
               ,SMALL_FIELD_LEN
              );
        */

        for(u64 x = 0; x < MAX_CLIENTS; ++x){
            if(strncmp( clients[x].user_id
                       ,(const char*)(client_msg_buf + SMALL_FIELD_LEN)
                       ,SMALL_FIELD_LEN
                      ) == 0
              )
            {
                printf("\n[DEBUG] Server: New user_id logic parsing PKT_30.\n");
                printf("              : Found the sender userID's index!!  \n");
                printf("              : in_server: %s\nvs\nin_packet:  %s\n\n"
                       ,clients[x].user_id
                       ,(const char*)(client_msg_buf + SMALL_FIELD_LEN)
                      );
                printf("              : Setting found_user_ix to %lu\n", x);
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
        //printf("[OK]  Server: Found a matching packet_ID = 40\n\n");
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
        printf("[OK]  Server: Found a matching packet_ID = 50\n\n");
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
        printf("[OK]  Server: Found a matching packet_ID = 60\n\n");
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        
        if(bytes_read != expected_siz){
            status = 1;
            goto label_error;
        }
        
        /* If transmission is of a valid type and size, process it. */
        process_msg_60(client_msg_buf);
        
        break;            
    
    }
    
    /* Also do something in case it was a bad unrecognized transmission.  */
    
    default:{
        /* DO NOT REACT TO BAD PACKETS!! Drop them silently instead. */
        // printf("[WAR] Server: No valid packet type found in request.\n\n");
        break;    
    }
    
    } /* end switch */
    
    goto label_cleanup;
    
label_error:

    printf("[ERR] Server: MSG Type was %s but of wrong size or contents\n"
           "              or another error occurred, check log.\n\n"
           ,msg_type_str
          );
          
    printf("              Size was: %ld\n", bytes_read);
    printf("              Expected: %ld\n", expected_siz);
    printf("\n[OK]  Server: Discarding transmission.\n\n ");
           
label_cleanup: 

    free(msg_type_str);
    return status;
}

void* check_for_lost_connections(){

    time_t curr_time;

    while(1){
    
        sleep(5); /* Check for lost connections every 10 seconds. */

        pthread_mutex_lock(&mutex);
       
        curr_time = clock();

        //printf("\n[OK] Server: Detector of lost connections STARTED!\n\n");

        //printf("[OK]  Server: Checker for lost connections started!\n");
        
        /* Go over all user slots, for every connected client, check the last 
         * time they polled the server. If it's more than 5 seconds ago, assume 
         * a lost connection and boot the user's client machine from the server 
         * and any chatrooms they were guests in or the owner of.
         */      
        for(u64 i = 0; i < MAX_CLIENTS; ++i){
          
            /* DEBUG */

            if(clients[i].room_ix != 0){
                printf("[DEBUG] Server: check for user[%lu] in room[%lu] :   \n"
                       "                cur_time: %ld s | last_polled: %ld s \n"
                       ,i, clients[i].room_ix, (curr_time / CLOCKS_PER_SEC)
                       ,(clients[i].time_last_polled / CLOCKS_PER_SEC)
                      );
            }

            /* DEBUG */

            
            if( 
               (users_status_bitmask & (1ULL << (63ULL - i))) 
                &&
                (clients[i].room_ix != 0)
                &&
               (( ((double)(curr_time - clients[i].time_last_polled)) / CLOCKS_PER_SEC) > 20.0)
            )
            {
                printf("[ERR] Server: Caught an inactive connected client!\n"
                       "              Removing them from the server:\n"
                       "              user_slot_bitmask_ix: [%lu]\n"
                       "              this_user's_room_ix : [%lu]\n"
                       "              Time since last poll: %f seconds\n\n"
                       ,i
                       ,clients[i].room_ix
                       ,( ((double)(curr_time - clients[i].time_last_polled)) / CLOCKS_PER_SEC)
                );
                      
                remove_user(i);
            }
        } 
        
        /* Check for an interrupted connection in the middle of an attempted
         * login. We keep the time at which the current (only one at a time is
         * possible) login started. Under normal circumstances, it should finish
         * right away, as it's just 2 transmissions. Although extremely unlikely
         * it's still possible for a connection to be interrupted after the 1st
         * login request was sent and before the second login packet could be
         * sent by the client. In this case, the global memory region keeping 
         * the very short-lived shared secret and key pair only used to securely
         * transport the long-term public key and unlock it from here.
         *
         * To defend against such a scenario (be it caused by a real loss of 
         * network connection to the server, or a malicious person deliberately
         * trying to do this to DoS or otherwise attack the server), check the
         * time elapsed since the CURRENT login was started. If it's been over
         * 10 seconds, assume a lost connection - drop the login attempt and
         * unlock the global memory region for login cryptographic artifacts.
         */
        if( 
              temp_handshake_memory_region_isLocked == 1
            &&
              ( (curr_time - time_curr_login_initiated) > 10)       
          )
        {
            explicit_bzero(temp_handshake_buf, TEMP_BUF_SIZ);
            temp_handshake_memory_region_isLocked = 0;               
        }
        
        curr_time = clock();
        /*
        printf( "\n[OK] Server: Detector of lost connections ENDED: %s\n"
               ,ctime(&curr_time)
        );
        */
        pthread_mutex_unlock(&mutex);
    }
}

void* start_new_client_thread(void* ix_ptr){

    u8* client_msg_buf;
    ssize_t bytes_read;

    u32 status;
    
    u64 ix;
 
    memcpy(&ix, ix_ptr, sizeof(ix));

    printf("New client recv() loop thread started. INDEX: %lu\n", ix);

    pthread_mutex_lock(&mutex);

    /* Get the ix-th global pointer to point to this heap memory buffer so
     * that the client cleanup functionality can free() it later, since this
     * function enters an infinite recv() loop that is never exited, and thus
     * cannot free() it by itself when the client machine gets disconnected
     * from the Rosetta server.
     */
    client_payload_buffer_ptrs[ix] = calloc(1, MAX_MSG_LEN);

    pthread_mutex_unlock(&mutex);

    client_msg_buf = client_payload_buffer_ptrs[ix];

    memset(client_msg_buf, 0, MAX_MSG_LEN);

    while(1){

        /* Block on this recv call, waiting for a client's request. */
        //bytes_read = recv(client_socket_fd[ix], client_msg_buf,MAX_MSG_LEN,0);
        bytes_read = receive_payload(ix, client_msg_buf, MAX_MSG_LEN); 
        
        if(bytes_read == -1)
            printf("[ERR] Server loop: receive_payload() went bad!\n");

        pthread_mutex_lock(&mutex);

        status = identify_new_transmission(client_msg_buf, bytes_read, ix);

        if(status)
            printf("[ERR] Server: identifying new transmission went bad!\n");
           
        memset(client_msg_buf, 0, bytes_read);

        pthread_mutex_unlock(&mutex);
    }
}

int main(int argc, char* argv[]){

    u8  ret = 0;
    u32 status = 0;
    u64 curr_free_socket_ix;

    uint8_t thread_func_arg_buf[sizeof(curr_free_socket_ix)];

    /* Function pointer set to respective socket initialization routine. */
    
    int arg1;

    if(argc != 2){
        printf("[ERR] Server: Needs 1 cmd line arg: 0 = regular, 1 = RTF.\n");
        exit(1);
    }
 
    arg1 = atoi(argv[1]);

    /* Set 4 function pointers for the communication mechanism (socket type)  */

    /* If server started for Rosetta Test Framework, use AF_UNIX sockets. */
    if(arg1 == 1){
        init_communication = ipc_init_communication;
        transmit_payload   = ipc_transmit_payload;
        receive_payload    = ipc_receive_payload;  
        onboard_new_client = ipc_onboard_new_client;  
    }

    /* If server started for normal Rosetta texting, use Internet sockets. */
    else if(arg1 == 0){
        init_communication = tcp_init_communication;                             
        transmit_payload   = tcp_transmit_payload;                               
        receive_payload    = tcp_receive_payload;                                
        onboard_new_client = tcp_onboard_new_client;  
    }

    else{
        printf("[ERR] Server: command line argument must be 0 or 1.\n");
        exit(1);
    }

    /**************************************************************************/
        
    /* Initialize Linux Sockets API stuff, load cryptographic artifacts. */ 
    status = self_init();
    
    if(status){
        printf("[ERR] Server: Could not complete self initialization!\n"
               "              Critical - Terminating the server.\n\n"
              );
        exit(1);
    }
    
    printf("\n\n[OK]  Server: SUCCESS - Finished self initializing!\n\n");

    
    
    /* Begin the thread function that will, in parallel to the running server,
     * check every 10 seconds for any lost connections, identified by connected
     * clients that haven't polled us for pending messages in over 3 seconds.
     * The normal polling is every 0.2 seconds.
     */
    if( (pthread_create( &conn_checker_threadID
                        ,NULL
                        ,&check_for_lost_connections
                        ,NULL
                       ) 
        ) != 0
      )
    {
        printf("[ERR] Server: Could not begin the lost connection tracker!\n"
               "              Critical - Terminating the server.\n\n");  
        exit(1);
    }
    
    while(1){

        curr_free_socket_ix = next_free_socket_ix;

        /**********************************************************************/

        /* Block here until a newly seen client wants to log in to Rosetta. */

        ret = onboard_new_client(curr_free_socket_ix);

        if(ret)
            printf("[ERR] Server: accepting a newly seen client failed!\n");

        /**********************************************************************/

        printf("[DEBUG] Server -- [ix] before : [%lu]\n", curr_free_socket_ix);

        memcpy( thread_func_arg_buf
               ,&curr_free_socket_ix
               ,sizeof(curr_free_socket_ix)
              );

        pthread_mutex_lock(&mutex);

        /* Give this new client a thread on which their socket will be stuck
         * on a recv() call loop and send() whatever the msg processor needs to.
         */

        /* Start the recv() looping thread for this new client. */
        pthread_create(
            &(client_thread_ids[curr_free_socket_ix])
           ,NULL
           , start_new_client_thread
           ,(void*)thread_func_arg_buf
        );

        /* Reflect the new taken socket slot in the global status bitmask. */
        socket_status_bitmask |= (1ULL << (63ULL - curr_free_socket_ix));

        /* Find the next free socket index. */
        ++next_free_socket_ix;
        
        while(next_free_socket_ix < MAX_CLIENTS){
            if(!(socket_status_bitmask & (1ULL<<(63ULL - next_free_socket_ix))))
            {
                break;
            }
            ++next_free_socket_ix;
        }  

        pthread_mutex_unlock(&mutex);                  
    }
                 
    return 0;
}
