#include <errno.h>

#include "../lib/coreutil.h"

#define PRIVKEY_LEN      40   
#define PUBKEY_LEN       384
#define MAX_CLIENTS      64
#define MAX_PEND_MSGS    64
#define MAX_CHATROOMS    64
#define MAX_MSG_LEN      131072
#define MAX_TXT_LEN      1024
#define MAX_BIGINT_SIZ   12800
#define SMALL_FIELD_LEN  8 
#define TEMP_BUF_SIZ     16384
#define SESSION_KEY_LEN  32
#define ONE_TIME_KEY_LEN 32
#define INIT_AUTH_LEN    32
#define SHORT_NONCE_LEN  12
#define LONG_NONCE_LEN   16
#define HMAC_TRUNC_BYTES 8

#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))

/* Memory region for short-term cryptographic artifacts for a login handshake */
u8* temp_handshake_buf = NULL;

/* Whether the login handshake memory region is currently locked or not. */
u8 temp_handshake_memory_region_isLocked = 0;

struct connected_client{
    char user_id[SMALL_FIELD_LEN];
    u64  room_ix;
    u64  num_pending_msgs;
    u64  pending_msg_sizes[MAX_PEND_MSGS];
    u8*  pending_msgs[MAX_PEND_MSGS];
    u64  nonce_counter;
    
    time_t time_last_polled;
    
    bigint client_pubkey;
    bigint client_pubkey_mont;
    bigint shared_secret; 
};

struct chatroom{
    u64 num_people;
    u64 owner_ix;
    u64 room_id;
};

/* Bitmasks telling the server which client and room slots are currently free. 
 *
 * Begin populating room slots and user slots at index [1]. Reserve [0] for 
 * meaning that the user is not in any room at all.
 */
u64 users_status_bitmask = 0;
u64 rooms_status_bitmask = 0;

/* Bitmask telling the server which socket file descriptors are free to be
 * used to accept a new connection to a client machine and begin its recv() loop
 * thread function which it will be stuck on until they exit Rosetta.
 */
u64 socket_status_bitmask = 0;
u64 next_free_socket_ix = 1;

u64 next_free_user_ix = 1;
u64 next_free_room_ix = 1;

u8 server_privkey[PRIVKEY_LEN];

time_t time_curr_login_initiated;

pthread_mutex_t mutex;
pthread_t conn_checker_threadID;

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

struct connected_client clients[MAX_CLIENTS];

struct chatroom rooms[MAX_CHATROOMS];

/* Create thread_id's for every client machine's recv() loop thread. */
pthread_t client_thread_ids[MAX_CLIENTS];

/* A global array of pointers that point to the heap memory buffer used for
 * the i-th client machine thread's network payload. We need this global array
 * in order to be able to release the heap-allocated memory buffer back to the
 * process' dynamic memory allocator with free() AFTER the client machine has
 * been disconnected from the Rosetta server, since that thread function enters
 * an infinite recv() loop that never exits, and is thus unable to free its own
 * heap-allocated payload buffer by itself, so it has to be done by the function
 * that cleans up a client machine's in-server state, and it is to be done via
 * this global array of pointers.
 */
u8* client_payload_buffer_ptrs[MAX_CLIENTS]; 

bigint* M;  /* Diffie-Hellman prime modulus M.              */
bigint* Q;  /* Diffie-Hellman prime exactly dividing (M-1). */
bigint* G;  /* Diffie-Hellman generator.                    */
bigint* Gm; /* Montgomery Form of G.                        */
bigint* server_pubkey_bigint;
bigint  server_privkey_bigint;


#include "server-packet-functions.h"
#include "server-tcp-communications.h"
#include "server-ipc-communications.h"


/* This function pointer tells the server whether to communicate through
 * Unix Domain sockets, or through Internet sockets. If the server was started
 * by the Rosetta Testing Framework, communication with test clients (that are
 * emulated as local OS processes instead of real people texting on the system)
 * is done via local unix interprocess communications (AF_UNIX sockets). If the
 * server is to be run normally for real Rosetta users to tune in to chatrooms
 * and text each other, Internet sockets are employed for communication.
 *
 * These two methods of communication need different initialization code.
 * A command-line argument determines whether the server was started by the
 * testing framework or for the real system, and this in turn sets this
 * function pointer to the appropriate communications initialization function.
 */
uint8_t (*init_communications)(void);

/* First thing done when we start the Rosetta server - initialize it. */
u8 self_init(){

    FILE* privkey_dat;

    u8 status = 0;

    status = init_communications();

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
    privkey_dat = fopen( "/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/"
                           "bin/server_privkey.dat"
                        ,"r"
                       );
    
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
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_M.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
    
    /* 320-bit prime exactly dividing M-1, making M cryptographycally strong. */
    Q = get_bigint_from_dat
     ( 320
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_Q.dat"
      ,320
      ,MAX_BIGINT_SIZ
     );
    
    /* Diffie-Hellman generator G = G = 2^((M-1)/Q) */
    G = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_G.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/saved_Gm.dat"
      ,3071
      ,MAX_BIGINT_SIZ
     );
    
    server_pubkey_bigint = get_bigint_from_dat
     ( 3072
      ,"/home/hypervisor/tmp/repos/Rosetta-Secure-Texting/bin/server_pubkey.dat"
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

    if(status){
        free(temp_handshake_buf);    
    }

    return status;
}

u8 check_pubkey_exists(u8* pubkey_buf, u64 pubkey_siz){

    if(pubkey_siz < 300){
        printf("[ERR] Server: Passed a small PubKey Size: %lu\n", pubkey_siz);
        return 1;
    }

    /* Client slot has to be taken, clients size has to match, 
     * then pubkey can match. 
     */
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if(   (users_status_bitmask & (1ULL << (63ULL - i)))
           && (PUBKEY_LEN == pubkey_siz)
           && (memcmp(pubkey_buf,(clients[i].client_pubkey).bits,pubkey_siz)==0)
          )
        {
            printf("\n[ERR] Server: PubKey already exists for user[%lu]\n", i);
            return 10;
        }
    }
    
    return 0;
}

void add_pending_msg(u64 user_ix, u64 data_len, u8* data){

    /* Make sure the user has space in their list of pending messages. */
    if(clients[user_ix].num_pending_msgs == MAX_PEND_MSGS){
        printf("[ERR] Server: No space for pend_msgs of userix[%lu]\n",user_ix);
        return;
    }
    
    /* Make sure the message is within the maximum permitted message length. */
    if(data_len >= MAX_MSG_LEN){
        printf("[ERR] Server: Pend_msg of userix[%lu] is too long!\n", user_ix);
        printf("              The MSG length is: %lu bytes\n\n", data_len);
        return;
    }
    
    /* Warn the server operator the user has just reached the pend_msgs limit */
    /* While not dangerous right now, this is still considered an error.      */
    if(clients[user_ix].num_pending_msgs == (MAX_PEND_MSGS - 1)){
        printf("[ERR] Server: userix[%lu] reached pend_msgs limit!\n", user_ix);
    }
    
    /* num_pending_msgs conveniently doubles as a way to tell which pending
     * msg slot is the next free one for each user. If that user has 0 pending
     * msgs, fill the [0] slot. If they have 1 pending message, fill out the
     * second slot, which is [1], etc.
     */

    /* Proceed to add the pending message to the user's list of them. */
    memcpy( clients[user_ix].pending_msgs[clients[user_ix].num_pending_msgs]
           ,data
           ,data_len
    );
    
    clients[user_ix].pending_msg_sizes[clients[user_ix].num_pending_msgs] 
     = data_len;
     
    return;    
}

void remove_user_from_room(u64 sender_ix){

    u8* reply_buf;
    u64 reply_len;
    u64 tmp_packet_id;
    u64 saved_room_ix = clients[sender_ix].room_ix;

    /* If it's not the owner, just tell the others that the person has left. */
    if(sender_ix != rooms[clients[sender_ix].room_ix].owner_ix){
    
        /* Construct the message and send it to everyone else in the chatroom.*/
        reply_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        
        tmp_packet_id = PACKET_ID_50;
        memcpy(reply_buf, &tmp_packet_id, sizeof(u64));
        
        memcpy( reply_buf + SMALL_FIELD_LEN
               ,clients[sender_ix].user_id
               ,SMALL_FIELD_LEN
        );
        
        /* Compute a signature so the clients can authenticate the server. */
        signature_generate( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN
                           ,reply_buf + (reply_len - SIGNATURE_LEN)
                           ,&server_privkey_bigint, PRIVKEY_LEN
        );
        
        /* Let the other room guests know that a user has left: TYPE_50 */
        for(u64 i = 0; i < MAX_CLIENTS; ++i){
            if(  
                 (i != sender_ix) 
               && 
                 (clients[i].room_ix == clients[sender_ix].room_ix))
            {
                add_pending_msg(i, reply_len, reply_buf);
                
                printf("[OK]  Server: Added pending message to user[%lu] that\n"
                       "              user[%lu] left the room.\n",i,sender_ix
                      );   
            }
        }
        
        /* Server bookkeeping - a guest has left the chatroom they were in. */
        /* In this case, simply decrement the number of guests in the room. */
        rooms[clients[sender_ix].room_ix].num_people -= 1;
        clients[sender_ix].room_ix = 0;
        clients[sender_ix].num_pending_msgs = 0;
        
        for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
            memset(clients[sender_ix].pending_msgs[i], 0, MAX_MSG_LEN);
            clients[sender_ix].pending_msg_sizes[i] = 0;
        }
    }
    
    /* if it WAS the room owner, boot everyone else from the chatroom as well */
    else{
        printf("Removing OWNER of room[%lu]!\n", clients[sender_ix].room_ix);
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        
        tmp_packet_id = PACKET_ID_51;
        memcpy(reply_buf, &tmp_packet_id, sizeof(u64));
        
        /* Compute a signature so the clients can authenticate the server. */
        signature_generate( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN
                           ,reply_buf + (reply_len - SIGNATURE_LEN)
                           ,&server_privkey_bigint, PRIVKEY_LEN
        );
        
        /* Let the other room guests know that they've been booted: TYPE_51 */
        for(u64 i = 0; i < MAX_CLIENTS; ++i){
            if(  
                 (i != sender_ix) 
               && 
                 (clients[i].room_ix == clients[sender_ix].room_ix))
            {
                printf("[OK]  Server: Adding pending MSG to user[%lu] that\n"
                       "              they've been booted from the room.\n", i
                      );   

                add_pending_msg(i, reply_len, reply_buf);
            }
        }
        
        /* Reflect in the global chatroom index array that the room is free. */
        rooms_status_bitmask &= ~(1ULL << (63ULL - clients[sender_ix].room_ix));
        
        /* Bookkeeping - a room owner closed their chatroom. Boot everyone. */

        /* In this case, nullify the entire room's descriptor structure. */
        rooms[clients[sender_ix].room_ix].num_people = 0;
        rooms[clients[sender_ix].room_ix].owner_ix   = 0;
        rooms[clients[sender_ix].room_ix].room_id    = 0;

        printf("Got to last loop in remove_user_FROM_ROOM()!\n");

        for(u64 i = 0; i < MAX_CLIENTS; ++i){
        
            if(clients[i].room_ix == saved_room_ix) {

                clients[i].room_ix = 0;
                clients[i].num_pending_msgs = 0;
                
                for(size_t j = 0; j < MAX_PEND_MSGS; ++j){
                    memset(clients[i].pending_msgs[j], 0, MAX_MSG_LEN);
                    clients[i].pending_msg_sizes[j] = 0;
                }  
            }
        }
    }
    
    free(reply_buf);
    
    return;
}

/* Once we've verified the sender's message is of the expected length, 
 * authenticate them to make sure it's really coming from a legit registered
 * user of Rosetta.
 *
 * Incoming cryptographic signatures are always in the same memory buffer as the
 * signed data. Extract signatures with a simple offset from its beginning.
 */
u8 authenticate_client( u64 client_ix,  u8* signed_ptr
                       ,u64 signed_len, u64 sign_offset
                      )
{
    bigint *recv_e;
    bigint *recv_s;
    
    u64 s_offset = sign_offset;
    u64 e_offset = (sign_offset + sizeof(bigint) + PRIVKEY_LEN);
   
    u8 ret;
    
    /* Reconstruct the sender's signature as the two BigInts that make it up. */
    recv_s = (bigint*)(signed_ptr + s_offset);
    recv_e = (bigint*)(signed_ptr + e_offset);    
    
    recv_s->bits = calloc(1, MAX_BIGINT_SIZ);
    recv_e->bits = calloc(1, MAX_BIGINT_SIZ);
 
    memcpy( recv_s->bits
           ,signed_ptr + (sign_offset + sizeof(bigint))
           ,PRIVKEY_LEN
    );
    
    memcpy( recv_e->bits
           ,signed_ptr + (sign_offset + (2*sizeof(bigint)) + PRIVKEY_LEN)
           ,PRIVKEY_LEN
    );
       
    /*
    printf("[DEBUG] Server: Calling signature_validate with:\n");
    printf("[DEBUG] Server: client[%lu]'s pubkeyMONT:\n", client_ix);
    bigint_print_info(&(clients[client_ix].client_pubkey_mont));
    bigint_print_bits(&(clients[client_ix].client_pubkey_mont));
    printf("[DEBUG] Server: and signed things of length %lu:\n", signed_len);

    for(u64 i = 0; i < signed_len; ++i){
        printf("%03u ", *(signed_ptr + i) );
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");
    */
   
    /* Verify the sender's cryptographic signature. */
    ret = signature_validate(
                     Gm, &(clients[client_ix].client_pubkey_mont)
                    ,M, Q, recv_s, recv_e, signed_ptr, signed_len
    ); 

    free(recv_s->bits);
    free(recv_e->bits);

    return ret;
}

#include "server-packet-functions.h"

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
u8 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u32 sock_ix){

    printf("?? identifier entering?? \n");

    u64 transmission_type = 0;
    u64 found_user_ix;
    u64 text_msg_len;

    u64* aux_ptr64_clientmsgbuf = client_msg_buf;

    s64 expected_siz = 0;

    u32 status = 0;

    char *msg_type_str = calloc(1, 3);

    printf("?? right before printing socket[sock_ix]  \n");    
    printf("[OK]  Server: Entered packet identifier for socket[%u]\n", sock_ix);

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
         *   (3 * SMALL_FIELD_LEN) + AD_LEN + TXT_LEN + SIGNATURE_LEN 
         *
         *   where:
         *          - TXT_LEN is found in message's third small field.  
         *
         *          - AD_LEN is length of Associated Data:
         *              
         *                 AD_LEN = N * (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN)
         *     
         *                 where N = (number of people in sender's room) - 1
         */
         
        memcpy( &found_user_ix
               ,client_msg_buf + SMALL_FIELD_LEN
               ,sizeof(found_user_ix)
              );
        
        memcpy( &text_msg_len
               ,client_msg_buf + (2 * SMALL_FIELD_LEN)
               ,sizeof(text_msg_len)
              );

        aux_ptr64_clientmsgbuf = (u64*)(client_msg_buf + (2 * SMALL_FIELD_LEN));

        expected_siz =   (3 * SMALL_FIELD_LEN)
                       + ( 
                          (rooms[clients[found_user_ix].room_ix].num_people - 1)
                          *
                          (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len)
                         ) 
                       + *aux_ptr64_clientmsgbuf
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
        printf("[OK]  Server: Found a matching packet_ID = 40\n\n");
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
        
        printf("[WAR] Server: No valid packet type found in request.\n\n");
        /* Send the reply back to the client. */
        /*
        if(send(client_socket_fd[sock_ix], "fuck you", 8, 0) == -1){
            printf("[ERR] Server: Couldn't reply to a bad transmission.\n");
            status = 1;
            goto label_error;
        }
        
        else{
            printf("[OK]  Server: Replied to a bad transmission.\n");
        }
        */    
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

void remove_user(u64 removing_user_ix){
    
    int status;

    /* Might have to remove them from a room (as a guest or as the owner)
     * or simply from the server if they weren't in a room.
     */
    if(clients[removing_user_ix].room_ix != 0){
        remove_user_from_room(removing_user_ix);
    }
    
    /* Clear the user's descriptor, free their global user index slot. */
    /* But first free calloc()'d stuff during user creation!           */

    for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
        free(clients[removing_user_ix].pending_msgs[i]);
    }
    
    /* Deallocate the bits buffer of the client's long-term public key. */
    free(clients[removing_user_ix].client_pubkey.bits); 
    
    /* Deallocate the bits buffer of the their public key's Montgomery form. */ 
    free(clients[removing_user_ix].client_pubkey_mont.bits);      
    
    /* Deallocate the bits buffer holding our shared secret with this client. */
    free(clients[removing_user_ix].shared_secret.bits);

    memset(&(clients[removing_user_ix]), 0, sizeof(struct connected_client));

    users_status_bitmask &= ~(1ULL << (63ULL - removing_user_ix));

    status = pthread_cancel(client_thread_ids[removing_user_ix]);

    /* Free the network payload buffer this client's thread had allocated. */
    free(client_payload_buffer_ptrs[removing_user_ix]);

    if(status != 0){
        printf("[ERR] Server: Couldn't stop quitting client's recv thread.\n\n");
    }

    status = close(client_socket_fd[removing_user_ix]);

    if(status != 0){
        printf("[ERR] Server: Couldn't close quitting client's socket.\n\n");
    }

    /* Update next free socket slot if needed. */
    if(removing_user_ix < next_free_socket_ix){
        next_free_socket_ix = removing_user_ix;
    }

    /* Reflect in global socket bitmask that this socket is now free again. */
    socket_status_bitmask &= ~(1ULL << (63ULL - removing_user_ix));

    return;
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

    u8*  client_msg_buf;

    s64  bytes_read; 

    u32 status;
    u32 ix = *((u32*)ix_ptr);

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
        bytes_read = recv(client_socket_fd[ix], client_msg_buf, MAX_MSG_LEN, 0);

        if(bytes_read == -1 || bytes_read < 8){
            printf( "[ERR] Server: Couldn't recv() or too short, client[%u]\n\n"
                ,ix
            );
            perror("recv() failed, errno was set to");
            memset(client_msg_buf, 0, MAX_MSG_LEN);
            continue;
        }
        else{
            printf("[OK]  Server: Read %ld bytes from request by client[%u]\n\n" 
                  ,bytes_read, ix
            );
        }

        pthread_mutex_lock(&mutex);

        status = identify_new_transmission(client_msg_buf, bytes_read, ix);

        if(status){
            printf("\n\n****** WARNING ******\n\n"
                    "Error while processing a received "
                    "transmission, look at log to find it.\n"
            );    
        }   


        memset(client_msg_buf, 0, bytes_read);

        pthread_mutex_unlock(&mutex); 

    }
}

int main(int argc, char* argv[]){

    u32 status;
    u32 curr_free_socket_ix;

    /* Function pointer set to respective socket initialization routine. */
    
    int arg1 = argv[1];

    if(arg1 == 1){
        init_communications = init_ipc_listening;
        printf("[OK] Server: Function pointer set to unix domain sockets.\n");
    }
    else if(arg1 == 0){
        init_communications = init_tcp_listening;
        printf("[OK] Server: Function pointer set to Internet sockets.\n");
    }
    else{
        printf("Command line arg must be 0 or 1. It is: %8X. Exit.\n", arg1);
    }

    /* Initialize Linux Sockets API, load cryptographic keys and artifacts. */ 
    status = self_init();
    
    if(status){
        printf("[ERR] Server: Could not complete self initialization!\n"
               "              Critical - Terminating the server.\n\n"
              );
        return 1;
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
        ) != 0)
    {
        printf("[ERR] Server: Could not begin the lost connection tracker!\n"
               "              Critical - Terminating the server.\n\n");  
        return 1;          
    }
    
    while(1){


        /* Block on this accept() until a new client machine wants to connect */
        client_socket_fd[next_free_socket_ix] = 
        accept( listening_socket,
                (struct sockaddr*)(&(client_addresses[next_free_socket_ix])),
                &(clientLens[next_free_socket_ix])
        );

        curr_free_socket_ix = next_free_socket_ix;

        if(client_socket_fd[curr_free_socket_ix] == -1){
            printf("[ERR] Server: accept() failed to connect the socket.\n");
            perror("accept() failed, errno was set");
            continue;
        }
        printf("[OK] Server: Passed accept! Received a new conn!\n\n");

        pthread_mutex_lock(&mutex);

        /* Give this new client a thread on which their socket will be stuck
         * on a recv() call loop and send() whatever the msg processor needs to.
         */

        /* Start the recv() looping thread for this new client. */
        pthread_create(
            &(client_thread_ids[curr_free_socket_ix])
           ,NULL
           , start_new_client_thread
           ,((void*)(&curr_free_socket_ix))
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
