#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../lib/coreutil.h"

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
#define HMAC_TRUNC_BYTES 8

#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))

/* Memory region for short-term cryptographic artifacts for a login handshake */
u8* temp_handshake_buf;

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

/* Linux Sockets API related globals. */
int port = SERVER_PORT;
int listening_socket;
int optval1 = 1;
int optval2 = 2;

int client_socket_fd[MAX_CLIENTS];
struct sockaddr_in client_addresses[MAX_CLIENTS];  
socklen_t clientLens[MAX_CLIENTS];

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

struct sockaddr_in servaddr;

/* First thing done when we start the Rosetta server - initialize it. */
u64 self_init(){

    FILE* privkey_dat;

    for(socklen_t i = 0; i < MAX_CLIENTS; ++i){
        clientLens[i] = sizeof(struct sockaddr_in);
    }

    /* Allocate memory for the temporary login handshake memory region. */
    temp_handshake_buf = calloc(1, TEMP_BUF_SIZ);

    /* Initialize the server address structure. */
    servaddr.sin_family      = AF_INET;
    servaddr.sin_port        = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    /* Obtain the file descriptor for the listen()ing socket. */                                                    
    if( (listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("[ERR] Server: Could not open server socket. Aborting.\n");
        return 1;
    }
    
    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1)
    );  
      
    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2)
    );
            
    if( (bind(listening_socket, (struct sockaddr*)&servaddr, sizeof(servaddr))) 
        == -1
      )
    {
        printf("[ERR] Server: Bind() returned -1.\n");
        
        if(errno != 13){
            printf("[ERR] Server: bind() failed. Errno != 13. Aborting.\n");
            return 1;
        }
    }
       
    /* Put the listen()ing socket in a state of listening for connections. */
    if( (listen(listening_socket, MAX_SOCK_QUEUE)) == -1){
        printf("[ERR] Server: couldn't begin listen()ing. Aborting.\n");
        return 1;
    }
    
    /*  Server will use its private key to compute cryptographic signatures of 
     *  everything it transmits, so all users can authenticate it using the
     *  server's long-term public key they already have at install time.
     */
    privkey_dat = fopen("../bin/server_privkey.dat", "r");
    
    if(!privkey_dat){
        printf("[ERR] Server: couldn't open private key DAT file. Aborting.\n");
        return 1;
    }
    
    if(fread(server_privkey, 1, PRIVKEY_LEN, privkey_dat) != PRIVKEY_LEN){
        printf("[ERR] Server: couldn't get private key from file. Aborting.\n");
        fclose(privkey_dat);
        return 1;
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
    M = get_BIGINT_from_DAT
        (3072, "../bin/saved_M.dat\0", 3071, MAX_BIGINT_SIZ);
    
    /* 320-bit prime exactly dividing M-1, making M cryptographycally strong. */
    Q = get_BIGINT_from_DAT
        (320,  "../bin/saved_Q.dat\0", 320,  MAX_BIGINT_SIZ);
    
    /* Diffie-Hellman generator G = G = 2^((M-1)/Q) */
    G = get_BIGINT_from_DAT
        (3072, "../bin/saved_G.dat\0", 3071, MAX_BIGINT_SIZ);

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_BIGINT_from_DAT
     (3072, "../bin/saved_Gm.dat\0", 3071, MAX_BIGINT_SIZ);
    
    server_pubkey_bigint = get_BIGINT_from_DAT
        (3072, "../bin/server_pubkey.dat\0", 3071, MAX_BIGINT_SIZ);
    
    fclose(privkey_dat);
    
    /* Initialize the mutex that will be used to prevent the main thread and
     * the connection checker thread from getting into a race condition.
     */
    if (pthread_mutex_init(&mutex, NULL) != 0) { 
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n"); 
        return 1; 
    } 
    
    return 0;
}

u8 check_pubkey_exists(u8* pubkey_buf, u64 pubkey_siz){

    if(pubkey_siz < 300){
        printf("[ERR] Server: Passed a small PubKey Size: %lu\n", pubkey_siz);
        return 2;
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
            return 1;
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
    u64 saved_room_ix = clients[sender_ix].room_ix;

    /* If it's not the owner, just tell the others that the person has left. */
    if(sender_ix != rooms[clients[sender_ix].room_ix].owner_ix){
    
        /* Construct the message and send it to everyone else in the chatroom.*/
        reply_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        
        *((u64*)(reply_buf)) = PACKET_ID_50;
                
        memcpy( reply_buf + SMALL_FIELD_LEN
               ,clients[sender_ix].user_id
               ,SMALL_FIELD_LEN
        );
        
        /* Compute a signature so the clients can authenticate the server. */
        Signature_GENERATE( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN
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
        
        *((u64*)(reply_buf)) = PACKET_ID_51;
        
        /* Compute a signature so the clients can authenticate the server. */
        Signature_GENERATE( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN
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
       
    printf("[DEBUG] Server: Calling signature_validate with:\n");
    printf("[DEBUG] Server: client's pubkeyMONT:\n");
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

    /* Verify the sender's cryptographic signature. */
    ret = Signature_VALIDATE(
                     Gm, &(clients[client_ix].client_pubkey_mont)
                    ,M, Q, recv_s, recv_e, signed_ptr, signed_len
    ); 

    free(recv_s->bits);
    free(recv_e->bits);

    return ret;
}

/* A user requested to be logged in Rosetta:

    Client ----> Server

================================================================================
|        PACKET_ID_00         |   Client's short-term public key in the clear  |
|=============================|================================================|
|       SMALL_FIELD_LEN       |                    PUBKEY_LEN                  |
--------------------------------------------------------------------------------

*/
void process_msg_00(u8* msg_buf, u64 sock_ix){

    bigint  zero;
    bigint  Am; 
    bigint* A_s;
    bigint  b_s;
    bigint* B_s = NULL;
    bigint  X_s;
            
    u64  tempbuf_byte_offset = 0;
    u64  replybuf_byte_offset = 0;
        
    u64 PACKET_ID02 = PACKET_ID_02;
    u64 reply_len = SMALL_FIELD_LEN + PUBKEY_LEN + SIGNATURE_LEN;

    u8* reply_buf = calloc(1, reply_len);
    u8  signature_buf[SIGNATURE_LEN]; 
    u8* PACKET_ID02_addr = (u8*)(&PACKET_ID02);
    u8* Y_s;

    memset(signature_buf, 0, SIGNATURE_LEN);

    /* If the login handshake memory region is locked, that means another
     * client is currently in the process of logging in, and only one login
     * is allowed at a time, so reject this login attempt now.
     */
    if(temp_handshake_memory_region_isLocked != 0){
        printf(
            "[OK] Server: Caught a login attempt in the middle of another!\n"
            "             Rejecting this login attempt with packet_02.\n\n"
        );

        /* Construct the ROSETTA FULL reply message buffer */
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        free(reply_buf);
        reply_buf = calloc(1, reply_len);
    
        *((u64*)(reply_buf)) = PACKET_ID_02;
        
        Signature_GENERATE( M, Q, Gm, PACKET_ID02_addr, SMALL_FIELD_LEN 
                            ,reply_buf + SMALL_FIELD_LEN
                           ,&server_privkey_bigint, PRIVKEY_LEN
                          );
                          
/* A client tried logging in but should try later.
 
    Server ----> Client
  
================================================================================
| packet ID 02 |                         SIGNATURE                             | 
|==============|===============================================================|
|  SMALL_LEN   |                          SIG_LEN                              |
--------------------------------------------------------------------------------

*/
        
        if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
            printf("[ERR] Server: Couldn't send try-login-later message.\n");
        }
        else{
            printf("[OK]  Server: Told client to try login later.\n");
        }

        free(reply_buf);

        return;
    } 

    /* Construct a bigint out of the client's short-term public key.          */
    /* Here's where a constructor from a memory buffer and its length is good */
    /* Find time to implement one as part of the BigInt library.              */
    
    /* Allocate any short-term keys and other cryptographic artifacts needed for
     * the initial login handshake protocol in the designated memory region and
     * lock it, disallowing another parallel login attempt to corrupt them.
     */
    temp_handshake_memory_region_isLocked = 1;

    time_curr_login_initiated = clock();

    bigint_create(&X_s, MAX_BIGINT_SIZ, 0);
    
    A_s = (bigint*)(temp_handshake_buf);
    A_s->bits = calloc(1, MAX_BIGINT_SIZ);

    memcpy(A_s->bits, msg_buf + SMALL_FIELD_LEN, PUBKEY_LEN);

    A_s->size_bits = MAX_BIGINT_SIZ;
    
    A_s->used_bits = get_used_bits(msg_buf + SMALL_FIELD_LEN, PUBKEY_LEN);
                     
    A_s->free_bits = A_s->size_bits - A_s->used_bits;
    
    printf("[DEBUG] Server: Copied over client's short-term pubkey's bits:\n");
    printf("                (Before Get_Mong_Form) Its info and ALL bits:\n\n");
    bigint_print_info(A_s);
    bigint_print_all_bits(A_s);

    /* Check that (0 < A_s < M) and that (A_s^(M/Q) mod M = 1) */
    
    /* A "check non zero" function in the BigInt library would also be useful */
    
    bigint_create(&zero, MAX_BIGINT_SIZ, 0);
    bigint_create(&Am,   MAX_BIGINT_SIZ, 0);
    
    Get_Mont_Form(A_s, &Am, M);
    
    if(   ((bigint_compare2(&zero, A_s)) != 3) 
        || 
          ((bigint_compare2(M, A_s)) != 1)
        //||
        //  (check_pubkey_form(&Am, M, Q) == 0) 
      )
    {
        printf("[ERR] Server: Client's short-term public key is invalid.\n");
        printf("              Its info and ALL bits:\n\n");
        bigint_print_info(A_s);
        bigint_print_all_bits(A_s);
        goto label_cleanup;
    } 
    
    /*  Server generates its own short-term DH keys and a shared secret X:
     *    
     *       b_s = random in the range [1, Q)
     * 
     *       B_s = G^b_s mod M     <--- Montgomery Form of G.
     *   
     *       X_s = A_s^b_s mod M   <--- Montgomery Form of A_s.
     *
     *  Server extracts two keys and two values Y, N from byte regions in X:
     *
     *       KAB_s = X_s[0  .. 31 ]
     *       KBA_s = X_s[32 .. 63 ]
     *       Y_s   = X_s[64 .. 95 ]
     *       N_s   = X_s[96 .. 107] <--- 12-byte Nonce for ChaCha20.
     *
     *  These 6 things are all stored in the designated locked memory region.
     *  It already had the client's short-term public key in it, so that's 8
     *  cryptographic artifacts in the memory region in total.
     */

    /* Places only the BITS of the private key, not a BigInt object!! */
    gen_priv_key(PRIVKEY_LEN, (temp_handshake_buf + sizeof(bigint)));
   
    b_s.bits = (u8*)calloc(1, MAX_BIGINT_SIZ);
    memcpy(b_s.bits, temp_handshake_buf + sizeof(bigint), PRIVKEY_LEN);

    b_s.size_bits = MAX_BIGINT_SIZ;
    b_s.used_bits = get_used_bits(b_s.bits, PRIVKEY_LEN);
    b_s.free_bits = b_s.size_bits - b_s.used_bits;
    
    memset(temp_handshake_buf + sizeof(bigint), 0,    PRIVKEY_LEN);
    memcpy(temp_handshake_buf + sizeof(bigint), &b_s, sizeof(bigint));

    /* Interface generating a pub_key needs priv_key in a file. TODO: change! */
    save_BIGINT_to_DAT("temp_privkey.dat", &b_s);
  
    B_s = gen_pub_key(PRIVKEY_LEN, "temp_privkey.dat", MAX_BIGINT_SIZ);
    
    /* Place the server short-term pub_key also in the locked memory region. */
    memcpy((temp_handshake_buf + (2 * sizeof(bigint))), B_s, sizeof(bigint));
    
   /* X_s = A_s^b_s mod M */
   // X_s = (bigint*)(temp_handshake_buf + (3 * sizeof(bigint)));
    
    MONT_POW_modM(&Am, &b_s, M, &X_s);
    
    printf("[DEBUG] Server: X_s computed on Server side:\n");
    bigint_print_info(&X_s);
    bigint_print_bits(&X_s);

    /* Extract KAB_s, KBA_s, Y_s and N_s into the locked memory region. */
    tempbuf_byte_offset = 3 * sizeof(bigint);
    
    memcpy( temp_handshake_buf + tempbuf_byte_offset
           ,X_s.bits
           ,SESSION_KEY_LEN
    );

    tempbuf_byte_offset += SESSION_KEY_LEN;
    
    memcpy( temp_handshake_buf + tempbuf_byte_offset
           ,X_s.bits + SESSION_KEY_LEN
           ,SESSION_KEY_LEN
    );
 
    tempbuf_byte_offset += SESSION_KEY_LEN;
    
    memcpy( temp_handshake_buf + tempbuf_byte_offset
           ,X_s.bits + (2 * SESSION_KEY_LEN)
           ,INIT_AUTH_LEN
    );
    
    Y_s = temp_handshake_buf + tempbuf_byte_offset;
        
    tempbuf_byte_offset += INIT_AUTH_LEN;
    
    memcpy( temp_handshake_buf + tempbuf_byte_offset
           ,X_s.bits + ((2 * SESSION_KEY_LEN) + (INIT_AUTH_LEN))
           ,SHORT_NONCE_LEN
    );
   
    printf("[DEBUG] Server: Y_s on which we COMPUTE signature:\n");
    printf("[DEBUG] Server: Y_s size 32 bytes:\n");

    for(u64 i = 0; i < INIT_AUTH_LEN; ++i){
        printf("%03u ", Y_s[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("[DEBUG] Server: Calling Signature_GENERATE now.\n\n");

    /* Compute a signature of Y_s using LONG-TERM private key b, yielding SB. */
    Signature_GENERATE( M, Q, Gm, Y_s, INIT_AUTH_LEN, signature_buf
                       ,&server_privkey_bigint, PRIVKEY_LEN
                      );



    /* Server sends in the clear (B_s, SB) to the client. */
    
    /* Find time to change the signature generation to only place the actual
     * bits of s and e, excluding their bigint structs, because we reconstruct
     * their bigint structs easily with get_used_bits(). TODO.
     */
    
    /* Construct the reply buffer. */ 
    
/* Send the client our short-term public key, so their software can compute a
   shared secret and transport their long-term public key in encrypted form.
   
    Server ----> Client

================================================================================
| PACKET_ID_00 | Server's one time PubKey | Signature of unused part of X: Y_s |
|==============|==========================|====================================|
|  SMALL_LEN   |       PUBKEY_LEN         |             SIGNATURE_LEN          |
--------------------------------------------------------------------------------

*/  
    replybuf_byte_offset = 0;
     
    *((u64*)(reply_buf + replybuf_byte_offset)) = PACKET_ID_00;
    
    replybuf_byte_offset += SMALL_FIELD_LEN;

    memcpy(reply_buf + replybuf_byte_offset, B_s->bits, PUBKEY_LEN);
    
    replybuf_byte_offset += PUBKEY_LEN;

    memcpy(reply_buf + replybuf_byte_offset, signature_buf, SIGNATURE_LEN);
    
    /* Send the reply back to the client. */
    if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
        printf("[ERR] Server: Couldn't reply with PACKET_ID_00 msg.\n");
    }
    else{
        printf("[OK]  Server: Replied to client with PACKET_ID_00 msg.\n");
    }
      
label_cleanup: 

    free(zero.bits);
    free(Am.bits);
    free(reply_buf);
    free(X_s.bits);

    if(B_s != NULL){
        free(B_s);
    }

    system("rm temp_privkey.dat");
  
    return;
}
/* A user who's logging in continued the login protocol, sending us their long
   term public key encrypted by the short-term shared secret with the server.
 
    Client ----> Server
 
================================================================================
|  packet ID 01   | Client's encrypted long-term PubKey |  HMAC authenticator  |
|=================|=====================================|======================|
| SMALL_FIELD_LEN |             PUBKEY_LEN              |   HMAC_TRUNC_BYTES   |
--------------------------------------------------------------------------------

*/
void process_msg_01(u8* msg_buf, u64 sock_ix){

    u64 handshake_buf_key_offset;
    u64 handshake_buf_nonce_offset;
    const u64 B = 64;
    const u64 L = 64;
    u64 PACKET_ID02 = PACKET_ID_02;
    u64 PACKET_ID01 = PACKET_ID_01; 
    u64 recv_HMAC_offset = SMALL_FIELD_LEN + PUBKEY_LEN;
    u64 reply_len;
    
    u8* PACKET_ID02_addr = (u8*)(&PACKET_ID02);
    u8* PACKET_ID01_addr = (u8*)(&PACKET_ID01);
    u8  K0[B];
    u8  ipad[B];
    u8  opad[B];
    u8  K0_XOR_ipad_TEXT[(B + PUBKEY_LEN)];
    u8  BLAKE2B_output[L]; 
    u8  last_BLAKE2B_input[B + L];
    u8  K0_XOR_ipad[B];
    u8  K0_XOR_opad[B];
    u8  HMAC_output[HMAC_TRUNC_BYTES];
    u8  client_pubkey_buf[PUBKEY_LEN];
    u8* reply_buf = NULL;
    
    bigint* temp_ptr;

    memset(K0, 0, B);
    memset(K0_XOR_ipad_TEXT, 0, (B + PUBKEY_LEN));
    memset(BLAKE2B_output, 0, L);
    memset(last_BLAKE2B_input, 0, B + L);
    memset(K0_XOR_ipad, 0, B);
    memset(K0_XOR_opad, 0, B);
    memset(HMAC_output, 0, HMAC_TRUNC_BYTES);
    memset(client_pubkey_buf, 0, PUBKEY_LEN);

    memset(opad, 0x5c, B);
    memset(ipad, 0x36, B);
    
    printf("[DEBUG] Server: Printing received msg_01 of length %u bytes:\n",
            SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES
    );

    for(u64 i = 0; i < SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES; ++i){
        printf("%03u ", (msg_buf)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

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
     
    /* Step 3 of HMAC construction */
    
    /* Length of K is less than B so append 0s to it until it's long enough. */
    /* This was done during K0's initialization. Now place the actual key.    */
    memcpy( K0
           ,temp_handshake_buf + (3 * sizeof(bigint))
           ,SESSION_KEY_LEN
          );

    printf("[DEBUG] Server: HMAC Step 3 produced K0:\n");

    for(u64 i = 0; i < B; ++i){
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
    
    printf("[DEBUG] Server: HMAC Step 4 produced K0_XOR_ipad: 64 bytes:\n");

    for(u64 i = 0; i < B; ++i){
        printf("%03u ", K0_XOR_ipad[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* step 5 of HMAC construction */
    memcpy(K0_XOR_ipad_TEXT, K0_XOR_ipad, B);
    memcpy(K0_XOR_ipad_TEXT + B, msg_buf + SMALL_FIELD_LEN, PUBKEY_LEN);
    
    printf("[DEBUG] Server: HMAC Step 5 produced K0_XOR_ipad_TEXT: 448 bytes:\n");

    for(u64 i = 0; i < B + PUBKEY_LEN; ++i){
        printf("%03u ", K0_XOR_ipad_TEXT[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* step 6 of HMAC construction */
    /* Call BLAKE2B on K0_XOR_ipad_TEXT */ 
    BLAKE2B_INIT(K0_XOR_ipad_TEXT, B + PUBKEY_LEN, 0, L, BLAKE2B_output);
    
    printf("[DEBUG] Server: HMAC Step 6 produced BLAKE2B_output: 64 bytes:\n");

    for(u64 i = 0; i < L; ++i){
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
    
   printf("[DEBUG] Server: HMAC Step 7 produced K0_XOR_opad: 64 bytes:\n");

    for(u64 i = 0; i < B; ++i){
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
    
   printf("[DEBUG] Server: HMAC Step 8 produced last_BLAKE2B_input: 192 bytes:\n");

    for(u64 i = 0; i < B + L; ++i){
        printf("%03u ", last_BLAKE2B_input[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Step 9 of HMAC construction */ 
    /* Call BLAKE2B on the combined buffer in step 8. */
    BLAKE2B_INIT(last_BLAKE2B_input, B + L, 0, L, BLAKE2B_output);
    
   printf("[DEBUG] Server: HMAC Step 9 produced BLAKE2B_output: 64 bytes:\n");

    for(u32 i = 0; i < L; ++i){
        printf("%03u ", BLAKE2B_output[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");

    /* Take the HMAC_TRUNC_BYTES leftmost bytes to form the HMAC output. */
    memcpy(HMAC_output, BLAKE2B_output, HMAC_TRUNC_BYTES);
    
    printf("[DEBUG] Server: Produced these 8 bytes of HMAC:\n");

    for(u32 i = 0; i < HMAC_TRUNC_BYTES; ++i){
        printf("%03u ", BLAKE2B_output[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }
    printf("\n\n");  

    printf("[DEBUG] Server: (1) To be checked against received HMAC 8 bytes\n");

    for(u32 i = 0; i < HMAC_TRUNC_BYTES; ++i){
        printf("%03u ", msg_buf[recv_HMAC_offset + i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    printf("[DEBUG] Server: (2) To be checked against received HMAC 8 bytes\n");

    for(u32 i = 0; i < HMAC_TRUNC_BYTES; ++i){
        printf("%03u ", (msg_buf + recv_HMAC_offset)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    /* Now compare calculated HMAC with the HMAC the client sent us */
    for(u64 i = 0; i < HMAC_TRUNC_BYTES; ++i){
        if(HMAC_output[i] != msg_buf[recv_HMAC_offset + i]){
            printf("[ERR] Server: HMAC authentication codes don't match!\n\n");
            printf("[OK]  Server: Discarding transmission.\n");
            goto label_cleanup;
        }
    }
    
    printf("[OK]  Server: HMAC authentication for logging-in client passed!\n");
    
    /*  Server uses KAB_s as key and 12-byte N_s as Nonce in ChaCha20 to
     *  decrypt A_x, revealing the client's long-term DH public key A.
     *
     *  Server then destroys all cryptographic artifacts for handshake. 
     */
    handshake_buf_nonce_offset = 
    (3 * sizeof(bigint)) + (2 * SESSION_KEY_LEN) + INIT_AUTH_LEN;

    handshake_buf_key_offset =  3 * sizeof(bigint);
    
    printf("[DEBUG] Server: ChaCha to decrypt client's long-term pubkey:\n");
    printf("input text: client's encrypted pubkey:\n");

    for(u64 i = 0; i < PUBKEY_LEN; ++i){
        printf("%03u ", (msg_buf + SMALL_FIELD_LEN)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    printf("input SHORT nonce:\n");

    for(u64 i = 0; i < SHORT_NONCE_LEN; ++i){
        printf("%03u ", (temp_handshake_buf + handshake_buf_nonce_offset)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    printf("Input chacha key of SESSION_KEY_LEN:\n");

    for(u64 i = 0; i < SESSION_KEY_LEN; ++i){
        printf("%03u ", (temp_handshake_buf + handshake_buf_key_offset)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    /* Passed parameters to this call to ChaCha20:
     *
     *  1. INPUT TEXT   : Client's encrypted long-term public key.
     *  2. TEXT_length  : in bytes.
     *  3. ChaCha Nonce : inside the locked global handshake memory region.
     *  4. Nonce_length : in uint32_t's.
     *  5. ChaCha Key   : inside the locked global handshake memory region
     *  6. Key_length   : in uint32_t's.
     *  7. Destination  : Pointer to where ChaCha's result should go.
     */
    CHACHA20(msg_buf + SMALL_FIELD_LEN
            ,PUBKEY_LEN
            ,(u32*)(temp_handshake_buf + handshake_buf_nonce_offset)
            ,(u32)(SHORT_NONCE_LEN / sizeof(u32))       
            ,(u32*)(temp_handshake_buf + handshake_buf_key_offset)
            ,(u32)(SESSION_KEY_LEN / sizeof(u32))
            ,client_pubkey_buf
            );
    
    printf("Resulted in this real client's public key:\n");

    /* Increment the Nonce to not reuse it when encrypting the user's index. */        
    ++(*((u64*)(temp_handshake_buf + handshake_buf_nonce_offset)));  
         
    /* Now we have the decrypted client's long-term public key. */
     
    /* If a message arrived to permit a newly arrived user to use Rosetta, but
     * currently the maximum number of clients are using it ---> Try later.
     */
    if(next_free_user_ix == MAX_CLIENTS){
        printf("[ERR] Server: Not enough client slots to let a user in.\n");
        printf("              Letting the user know and to try later.  \n");
        
        /* Construct the ROSETTA FULL reply message buffer */
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
    
        *((u64*)(reply_buf)) = PACKET_ID_02;
        
        Signature_GENERATE( M, Q, Gm, PACKET_ID02_addr, SMALL_FIELD_LEN 
                            ,reply_buf + SMALL_FIELD_LEN
                           ,&server_privkey_bigint, PRIVKEY_LEN
                          );
                          
/* A client tried logging in but should try later.
 
    Server ----> Client
  
================================================================================
| packet ID 02 |                         SIGNATURE                             | 
|==============|===============================================================|
|  SMALL_LEN   |                          SIG_LEN                              |
--------------------------------------------------------------------------------

*/
        
        if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
            printf("[ERR] Server: Couldn't send try-login-later message.\n");
        }
        else{
            printf("[OK]  Server: Told client to try login later.\n");
        }
        goto label_cleanup;
    }
    
    if( (check_pubkey_exists(client_pubkey_buf, PUBKEY_LEN)) > 0 ){
        printf("[ERR] Server: Obtained login public key already exists.\n");
        printf("\n[OK]  Server: Discarding transmission.\n");
        goto label_cleanup;
    }
    
    /* Construct the login OK reply message buffer. */
    /* It will contain the user index */
    /* Encrypt the index with chacha20 and KBA key and N_s nonce! */
    
    /* Try using a chacha counter even with less than 64 bytes of input. */
    reply_len  = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
    reply_buf  = calloc(1, reply_len);
    
    *((u64*)(reply_buf)) = PACKET_ID_01;
    
    handshake_buf_key_offset  = (3 * sizeof(bigint)) + (1 * SESSION_KEY_LEN);
    
    CHACHA20((u8*)(&next_free_user_ix)
             ,SMALL_FIELD_LEN
             ,(u32*)(temp_handshake_buf + handshake_buf_nonce_offset)
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32))
             ,(u32*)(temp_handshake_buf + handshake_buf_key_offset)
             ,(u32)(SESSION_KEY_LEN / sizeof(u32))
             ,(reply_buf + SMALL_FIELD_LEN)
             );
             
    /* No need to increment this Nonce because it will be destroyed */
    Signature_GENERATE( M, Q, Gm, PACKET_ID01_addr, SMALL_FIELD_LEN
                       ,(reply_buf+ (2 * SMALL_FIELD_LEN))
                       ,&server_privkey_bigint, PRIVKEY_LEN
                      );
    
    /* Server bookkeeping - populate this user's slot, find next free slot. */
  
    clients[next_free_user_ix].room_ix          = 0;
    clients[next_free_user_ix].num_pending_msgs = 0;
    clients[next_free_user_ix].nonce_counter    = 0;
    clients[next_free_user_ix].time_last_polled = clock();

    for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
        clients[next_free_user_ix].pending_msgs[i] = calloc(1, MAX_MSG_LEN);
    }
    
    memset( clients[next_free_user_ix].pending_msg_sizes
           ,0
           ,(MAX_PEND_MSGS * SMALL_FIELD_LEN)
          );

    /* Transport the client's long-term public key into their slot. */
    bigint_create( &(clients[next_free_user_ix].client_pubkey)
                  ,MAX_BIGINT_SIZ
                  ,0
                 ); 
    
    memcpy( (clients[next_free_user_ix].client_pubkey).bits
            ,client_pubkey_buf
            ,PUBKEY_LEN
          );
    
    (clients[next_free_user_ix].client_pubkey).used_bits 
     = get_used_bits(client_pubkey_buf, PUBKEY_LEN);
     
    (clients[next_free_user_ix].client_pubkey).free_bits
    = MAX_BIGINT_SIZ - (clients[next_free_user_ix].client_pubkey).used_bits;
    
    printf("[DEBUG] Server: obtained client's real public key from chacha20\n");

    bigint_print_info(&(clients[next_free_user_ix].client_pubkey));
    bigint_print_bits(&(clients[next_free_user_ix].client_pubkey));
    printf("\n\n ALL BITS of the client's real public key:\n\n");
    bigint_print_all_bits(&(clients[next_free_user_ix].client_pubkey));
    printf("\n ALSO the decrypted pubkey bits placed in pubkey_buf:\n");

    for(u64 i = 0; i < PUBKEY_LEN; ++i){
        printf("%03u ", (client_pubkey_buf)[i]);
        if(((i+1) % 8 == 0) && i > 6){
            printf("\n");
        }
    }

    /* Calculate the Montgomery Form of the client's long-term public key. */ 
    bigint_create( &(clients[next_free_user_ix].client_pubkey_mont)
                  ,MAX_BIGINT_SIZ
                  ,0
                 );      
          
    Get_Mont_Form( &(clients[next_free_user_ix].client_pubkey)
                  ,&(clients[next_free_user_ix].client_pubkey_mont)
                  ,M
                 );      
               
     
    /* Compute a client-to-server encryption shared secret which will be used
     * to encrypt transmissions that occur before the client has started to
     * actually talk to other clients, so before the client-to-client encryption
     * shared secret comes into play.
     *
     * For client-to-client encryption, the server will have to transmit to all
     * clients the long-term public keys of all clients they need to talk to.
     * This is another usage of the client-to-server shared secret.
     *
     * The server will maintain its own shared secret with a client by placing
     * it in that client's structure entry, just like it keeps the client's
     * public key there too.
     */
    bigint_create( &(clients[next_free_user_ix].shared_secret)
                  ,MAX_BIGINT_SIZ
                  ,0
                 );
    
    MONT_POW_modM( &(clients[next_free_user_ix].client_pubkey_mont)
                  ,&server_privkey_bigint
                  ,M
                  ,&(clients[next_free_user_ix].shared_secret)
                 );
    
    /* Reflect the new taken user slot in the global user status bitmask. */
    users_status_bitmask |= 
                       (1ULL << (63ULL - next_free_user_ix));
    
    /*  Increment it one space to the right, since we're guaranteeing by
     *  logic in the user erause algorithm that we're always filling in
     *  a new user in the LEFTMOST possible empty slot.
     *
     *  If you're less than (max_users), look at this slot and to the right
     *  in the bitmask for the next leftmost empty user slot index. If you're
     *  equal to (max_users) then the maximum number of users are currently
     *  using Rosetta. Can't let any more people in until one leaves.
     *
     *  Here you either reach MAX_CLIENTS, which on the next attempt to 
     *  let a user in and fill out a user struct for them, will indicate
     *  that the maximum number of people are currently using Rosetta, or
     *  you reach a bit at an index less than MAX_CLIENTS that is 0 in the
     *  global user slots status bitmask.
     */
    ++next_free_user_ix;
    
    while(next_free_user_ix < MAX_CLIENTS){
        if(!( users_status_bitmask & (1ULL << (63ULL - next_free_user_ix)))){
            break;
        }
        ++next_free_user_ix;
    }

/* A client successfully logged in. Let them know what their user_ix is.    
 
    Server ----> Client
  
================================================================================
| packet ID 01 |  user_ix  |                    SIGNATURE                      | 
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
      
    if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
        printf("[ERR] Server: Couldn't send Login-OK message.\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Told client Login went OK, sent their index.\n");
    }
    
    printf("\n\n[OK]  Server: SUCCESS - Permitted a user in Rosetta!!\n\n");

label_cleanup:

    /* Now it's time to clear and unlock the temporary login memory region. */
    temp_ptr = (bigint*)temp_handshake_buf;
    free(temp_ptr->bits);

    temp_ptr = (bigint*)(temp_handshake_buf + sizeof(bigint));
    free(temp_ptr->bits);

    temp_ptr = (bigint*)(temp_handshake_buf + (2 * sizeof(bigint)));
    free(temp_ptr->bits);

    memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);

    temp_handshake_memory_region_isLocked = 0;     

    printf("[OK]  Server: Handshake memory region has been released!\n\n");
    
    if(reply_buf){
        free(reply_buf);
    }
    
    return ;
}

/* A client requested to create a new chatroom.
 
                                          ENCRYPTED
                            /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
================================================================================
| packet ID 10 |  user_ix  | Decryption Key   | Room_ID+user_ID |  Signature   |
|==============|===========|==================|=================|==============|
|  SMALL_LEN   | SMALL_LEN | ONE_TIME_KEY_LEN |  2 * SMALL_LEN  | SIGNATURE_LEN|
--------------------------------------------------------------------------------

*/
void process_msg_10(u8* msg_buf, u32 sock_ix){
        
    u8 nonce[LONG_NONCE_LEN];
    u8 KAB[SESSION_KEY_LEN];
    u8 KBA[SESSION_KEY_LEN];
    u8 recv_K[ONE_TIME_KEY_LEN];
    u8 send_K[ONE_TIME_KEY_LEN];
    u8 room_user_ID_buf[2 * SMALL_FIELD_LEN];
    u8* reply_buf = NULL;

    u64 reply_len;
    u64 user_ix;
    u64 PACKET_ID11    = PACKET_ID_11;
    u64 PACKET_ID10    = PACKET_ID_10;
    u64 signed_len     = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 room_id_offset = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 sign_offset    = signed_len;

    bigint nonce_bigint;
    bigint one;
    bigint aux1;

    memset(nonce,            0, LONG_NONCE_LEN);
    memset(KAB,              0, SESSION_KEY_LEN);
    memset(KBA,              0, SESSION_KEY_LEN);
    memset(recv_K,           0, ONE_TIME_KEY_LEN);
    memset(send_K,           0, ONE_TIME_KEY_LEN);
    memset(room_user_ID_buf, 0, 2 * SMALL_FIELD_LEN);

    user_ix = *((u64*)(msg_buf + SMALL_FIELD_LEN));

    /* - Fetch this user_ix's nonce from shared secret at byte [64] for 16 bytes
     * - Turn it into a temporary BigInt
     */

    /* Another instance of a BigInt constructor from mem. Find time for it. */
    /* MAX_BIGINT_SIZ is in bits, so divide by 8 to get the reserved BYTES. */
    nonce_bigint.bits = calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));
    
    memcpy( nonce_bigint.bits
           ,clients[user_ix].shared_secret.bits + (2 * SESSION_KEY_LEN)
           ,LONG_NONCE_LEN
    );
     
    nonce_bigint.used_bits = get_used_bits(nonce_bigint.bits, LONG_NONCE_LEN);
    nonce_bigint.size_bits = MAX_BIGINT_SIZ;
    nonce_bigint.free_bits = MAX_BIGINT_SIZ - nonce_bigint.used_bits;
    
    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

    /* Verify the sender's cryptographic signature to make sure they're legit */
    if( authenticate_client(user_ix, msg_buf, signed_len, sign_offset) != 1){
        printf("[ERR] Server: Invalid signature. Discarding transmission.\n\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }
    
    /*  On server's side: 
     *       - KBA = least significant 32 bytes of shared secret
     *       - KAB = next 32 bytes of shared secret
     *       - swap KBA with KAB if A > B.
     *
     *  Here the server needs KAB to decrypt KB into one-time-use key K, behind
     *  which is hidden the desired room index of the room they want to create.
     */
    
    if(
       bigint_compare2(&(clients[user_ix].client_pubkey), server_pubkey_bigint) 
        == 3
      )
    {
        memcpy( KBA
               ,(clients[user_ix].shared_secret).bits
               ,SESSION_KEY_LEN
        );
        memcpy( KAB
               ,(clients[user_ix].shared_secret).bits + SESSION_KEY_LEN
               ,SESSION_KEY_LEN
        );
    }
    else{
      /* KAB is the FIRST 32 bytes of shared secret in this case, not next. */
      /* KBA is next 32 bytes. */   
        memcpy( KAB
               ,(clients[user_ix].shared_secret).bits
               ,SESSION_KEY_LEN
        );
        memcpy( KBA
               ,(clients[user_ix].shared_secret).bits + SESSION_KEY_LEN
               ,SESSION_KEY_LEN
        ); 
    }
    
     /*
     * - Add 1 to it as many times as this user_ix's nonce_counter says
     * - Turn that incremented nonce back into a buffer pointed to by a u32*
     * - Use that nonce in the call to ChaCha20 that gets us the one-use key K
     * - Increment the nonce
     * - Implement the rest of the response:
     *      - Use K in another ChaCha20 call with nonce+1 to get room_ID
     *      - Increment the nonce again, save it.
     *      - If enough space for a new room, create it.
     *      - Do any required server bookkeeping for global arrays and indices.
     *      - Send a reply either saying OK, or not enough space for new rooms.
     */
     
    /* Increment nonce as many times as needed. */
    for(u64 i = 0; i < clients[user_ix].nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }
    
    CHACHA20( msg_buf + (2 * SMALL_FIELD_LEN)      /* text - key KB           */
             ,SESSION_KEY_LEN                      /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output target buffer    */
             );
   
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    ++(clients[user_ix].nonce_counter);
   
    /* Now use the decrypted key to decrypt room_ID and user_ID. */
   
    CHACHA20( msg_buf + room_id_offset             /* text: encr room+user_ID */
             ,2 * SMALL_FIELD_LEN                  /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* key_len in uint32_t's   */
             ,room_user_ID_buf                     /* output target buffer    */
            );
  
    /* Increment nonce counter again to prepare the nonce for its next use. */
    ++(clients[user_ix].nonce_counter); 

    /* Now that we have the room_ID, create a new chatroom if space allows. */
    
    /* If not enough space for new chatrooms currently, tell the client. */
    if(next_free_room_ix == MAX_CHATROOMS){
        printf("[ERR] Server: Not enough room slots to make a new chatroom.\n");
        printf("              Letting the user know and to try later.  \n");
        
        /* Construct the NO ROOM SPACE AVAILABLE reply msg buffer:

================================================================================
|  packet ID 11   |                    Cryptographic Signature                 |
|=================|============================================================|
| SMALL_FIELD_LEN |                     SIGNATURE_LEN                          |
--------------------------------------------------------------------------------
        
        */
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);

        *((u64*)(reply_buf)) = PACKET_ID11;

        Signature_GENERATE( M, Q, Gm, (u8*)(&PACKET_ID11), SMALL_FIELD_LEN
                           ,reply_buf + SMALL_FIELD_LEN
                           ,&server_privkey_bigint, PRIVKEY_LEN
                          );
        
        if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
            printf("[ERR] Server: Couldn't send No Room Space message.\n");
        }
        else{
            printf("[OK]  Server: Told client No Room Space, try later.\n");
        }
        goto label_cleanup;  
    }
    
        /* Construct the ROOM CREATION WENT OKAY reply message buffer:

================================================================================
|  packet ID 10   |                    Cryptographic Signature                 |
|=================|============================================================|
| SMALL_FIELD_LEN |                     SIGNATURE_LEN                          |
--------------------------------------------------------------------------------
        
        */
    reply_len  = SMALL_FIELD_LEN + SIGNATURE_LEN;
    reply_buf  = calloc(1, reply_len);
           
    *((u64*)(reply_buf)) = PACKET_ID10;
    
    Signature_GENERATE( M, Q, Gm, (u8*)(&PACKET_ID10), SMALL_FIELD_LEN
                       ,(reply_buf + SMALL_FIELD_LEN)
                       ,&server_privkey_bigint, PRIVKEY_LEN
                      );
    
    /* Server bookkeeping - populate this room's slot, find next free slot. */
    rooms[next_free_room_ix].num_people = 1;
    rooms[next_free_room_ix].owner_ix = user_ix;
    rooms[next_free_room_ix].room_id = *((u64*)room_user_ID_buf);
    
    clients[user_ix].room_ix = next_free_room_ix;
    
    memcpy( clients[user_ix].user_id
           ,(room_user_ID_buf + SMALL_FIELD_LEN) 
           ,SMALL_FIELD_LEN
          );

    /* Reflect the new taken room slot in the global room status bitmask. */
    rooms_status_bitmask |= (1ULL << (63ULL - next_free_room_ix));
    
    /* Similar indexing logic to the one described by the large comment for
     * the user slot creation code.
     */
    ++next_free_room_ix;
    
    while(next_free_room_ix < MAX_CHATROOMS){
        if(!(rooms_status_bitmask & (1ULL << (63ULL - next_free_room_ix))))
        {
            break;
        }
        ++next_free_room_ix;
    }
    
    /* Transmit the server's ROOM CREATION OK reply back to the client. */    
    if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
        printf("[ERR] Server: Couldn't send RoomCreation-OK message.\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Told client room creation went OK!\n");
    }

label_cleanup:

    free(nonce_bigint.bits);
    free(one.bits);
    free(aux1.bits);

    if(reply_buf){ 
        free(reply_buf);
    }
    
    return;
}
 
/* A client requested to join an existing chatroom.
 
                                          ENCRYPTED
                            /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
================================================================================
| packet ID 20 |  user_ix  | Decryption Key   | Room_ID+user_ID |  Signature   |
|==============|===========|==================|=================|==============|
|  SMALL_LEN   | SMALL_LEN | ONE_TIME_KEY_LEN |  2 * SMALL_LEN  | SIGNATURE_LEN|
--------------------------------------------------------------------------------

*/
void process_msg_20(u8* msg_buf, u32 sock_ix){

    FILE* ran_file = NULL;

    const u64 buf_type_21_len = 
          (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + SIGNATURE_LEN + PUBKEY_LEN;

    u64 user_ix;
    u64 room_ix;
    u64 send_type20_signed_len;
    u64 user_ixs_in_room[MAX_CLIENTS];
    u64 buf_ixs_pubkeys_write_offset;
    u64 buf_ixs_pubkeys_len;
    u64 reply_len;
    u64 send_type21_encr_part_offset = SMALL_FIELD_LEN + ONE_TIME_KEY_LEN;
    u64 send_type20_AD_offset        = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 num_users_in_room            = 0;
    u64 next_free_room_users_ix      = 0;
    u64 encrypted_roomID_offset      = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN;
    u64 sign_offset                  = ONE_TIME_KEY_LEN + (4 * SMALL_FIELD_LEN);
    u64 signed_len                   = sign_offset;
                              
    u8  buf_type_21[buf_type_21_len];
    u8  room_user_ID_buf[2 * SMALL_FIELD_LEN];
    u8  KAB[SESSION_KEY_LEN];
    u8  KBA[SESSION_KEY_LEN];
    u8  recv_K[ONE_TIME_KEY_LEN];
    u8  send_K[ONE_TIME_KEY_LEN];
    u8  type21_encrypted_part[SMALL_FIELD_LEN + PUBKEY_LEN];
    u8* buf_ixs_pubkeys = NULL;
    u8* reply_buf = NULL;
    u8  room_found;
    
    size_t ret_val;
       
    bigint nonce_bigint;
    bigint one;
    bigint aux1;
        
    user_ix = *((u64*)(msg_buf + SMALL_FIELD_LEN));

    /* Early initializations and heap allocations. */

    nonce_bigint.bits = NULL;
    one.bits = NULL;
    aux1.bits = NULL;

    memset(buf_type_21,           0, buf_type_21_len);
    memset(room_user_ID_buf,      0, 2 * SMALL_FIELD_LEN);
    memset(KAB,                   0, SESSION_KEY_LEN);
    memset(KBA,                   0, SESSION_KEY_LEN);
    memset(recv_K,                0, ONE_TIME_KEY_LEN);
    memset(send_K,                0, ONE_TIME_KEY_LEN);
    memset(type21_encrypted_part, 0, SMALL_FIELD_LEN + PUBKEY_LEN);
    memset(user_ixs_in_room,      0, MAX_CLIENTS * sizeof(u32));

    bigint_create(&one,  MAX_BIGINT_SIZ, 1);
    bigint_create(&aux1, MAX_BIGINT_SIZ, 0);

    nonce_bigint.bits = calloc(1, ((size_t)((double)MAX_BIGINT_SIZ/(double)8)));

    /* Verify the sender's cryptographic signature to make sure they're legit */
    if( authenticate_client(user_ix, msg_buf, signed_len, sign_offset) != 1){
        printf("[ERR] Server: Invalid signature. Discarding transmission.\n\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }

    /*  On server's side: 
     *       - KBA = least significant 32 bytes of shared secret
     *       - KAB = next 32 bytes of shared secret
     *       - swap KBA with KAB if A > B.
     *
     *  Here the server needs KAB to decrypt KB into one-time-use key K, behind
     *  which is hidden the desired room index of the room they want to create.
     */
    
    if(
       bigint_compare2(&(clients[user_ix].client_pubkey), server_pubkey_bigint) 
        == 3
      )
    {
        memcpy( KBA
               ,(clients[user_ix].shared_secret).bits
               ,SESSION_KEY_LEN
        );
        memcpy( KAB
               ,(clients[user_ix].shared_secret).bits + SESSION_KEY_LEN
               ,SESSION_KEY_LEN
        );
    }
    else{
        /* KAB is the FIRST 32 bytes of shared secret in this case, not next. */
        /* KBA is next 32 bytes. */   
        memcpy( KAB
               ,(clients[user_ix].shared_secret).bits
               ,SESSION_KEY_LEN
        );
        memcpy( KBA
               ,(clients[user_ix].shared_secret).bits + SESSION_KEY_LEN
               ,SESSION_KEY_LEN
        ); 
    }
    
    /* - Fetch this user_ix's nonce from shared secret at byte [64] for 16 bytes
     * - Turn it into a temporary BigInt
     * - Add 1 to it as many times as this user_ix's nonce_counter says
     * - Turn that incremented nonce back into a buffer pointed to by a u32*
     * - Use that nonce in the call to ChaCha20 that gets us the one-use key K
     * - Increment the nonce
     * - Implement the rest of the response:
     *      - Use K in another ChaCha20 call with nonce+1 to get roomID + userID
     *      - Increment the nonce again, save it.
     *      - If enough space for a new room, create it.
     *      - Do any required server bookkeeping for global arrays and indices.
     *      - Send a reply either saying OK, or not enough space for new rooms.
     */
    
    /* Another instance of a BigInt constructor from mem. Find time for it. */
    /* MAX_BIGINT_SIZ is in bits, so divide by 8 to get the bytes.          */
    
    
    memcpy( nonce_bigint.bits
           ,clients[user_ix].shared_secret.bits + (2 * SESSION_KEY_LEN)
           ,LONG_NONCE_LEN
          ); 
          
    nonce_bigint.used_bits = get_used_bits(nonce_bigint.bits, LONG_NONCE_LEN);
    nonce_bigint.size_bits = MAX_BIGINT_SIZ;
    nonce_bigint.free_bits = MAX_BIGINT_SIZ - nonce_bigint.used_bits;
       
    /* Increment nonce as many times as needed. */
    for(u64 i = 0; i < clients[user_ix].nonce_counter; ++i){
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);     
    }
    
    CHACHA20( msg_buf + (2 * SMALL_FIELD_LEN)      /* text - one-time key KB  */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KAB)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,recv_K                               /* output target buffer    */
             );
   
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    ++(clients[user_ix].nonce_counter);
   
    /* Use the incremented nonce in the other call to chacha for user+roomID. */
   
    CHACHA20( msg_buf + encrypted_roomID_offset    /* text: encr room+user_ID */
             ,2 * SMALL_FIELD_LEN                  /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(recv_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* key_len in uint32_t's   */
             ,room_user_ID_buf                     /* output target buffer    */
            );
  
    /* Increment nonce counter again to prepare the nonce for its next use. */
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    ++(clients[user_ix].nonce_counter); 

    /* Now that we have room_id, check that it really exists. */
    room_found = 0;
    
    for(u64 i = 0; i < MAX_CHATROOMS; ++i){
        if(rooms[i].room_id == *((u64*)(room_user_ID_buf)) ){
            room_found = 1;
            room_ix = i;
            break;
        } 
    }
    
    /* If no room was found with this ID, silently drop communication. */
    if(!room_found){
        /* Don't tell the client that the room wasn't found.         */
        /* Could be someone hacking. Silently drop the transmission. */
        printf("[ERR] Server: A client requested to join an unknown room.\n");
        printf("              Dropping transmission silently.\n\n");
        goto label_cleanup;
    }

    /* Server bookkeeping */
    
    ++(rooms[room_ix].num_people);
    
    memcpy( clients[user_ix].user_id
           ,(room_user_ID_buf + SMALL_FIELD_LEN)
           ,SMALL_FIELD_LEN
          ); 

    /* Send (encrypted and signed) the public keys of all users currently in the
     * chatroom, to the user who is now wanting to join it, as well as the new 
     * client's public key to all people who are currently in the chatroom so 
     * they can derive shared secrets and pairs of bidirectional symmetric keys 
     * and other cryptographic artifacts like ChaCha encryption nonces.
     */
     
    /* First do the public keys of everyone in the room to new client part. */
     
    /* Iterate over all user indices, for the number of people in the room. */
    
    next_free_room_users_ix = 0;
    
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if(clients[i].room_ix == room_ix){
            ++num_users_in_room;
            user_ixs_in_room[next_free_room_users_ix] = i;
            ++next_free_room_users_ix;
        }
    }  
      
    /* Construct the message buffer. */
    buf_ixs_pubkeys_len = num_users_in_room * (SMALL_FIELD_LEN + PUBKEY_LEN);
    
    reply_len = (2 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN 
                  + 
                 SIGNATURE_LEN + buf_ixs_pubkeys_len;
                  
    reply_buf = calloc(1, reply_len);
           
    *((u64*)(reply_buf)) = PACKET_ID_20;
    
    /* Draw a random one-time use 32-byte key K, encrypt it with ChaCha20 using
     * KBA as chacha key and the server-client-maintained incremented Nonce from
     * the two's DH shared secret. Increment the Nonce. 
     *
     * Concatenate the encrypted one-time use key K, now KA, to PACKET_ID_2O.
     *
     * Fetch the user_id and public_key of all users currently in this chatroom.
     *
     * Use un-encrypted key K as ChaCha key to encrypt the actual protected part
     * of the transmission to the client, in this case:
     *
     * [num_keys_N + ( (user_ix1,public_key1)...(user_ixN,public_keyN) )]
     *
     * whose length in bytes is exactly:
     *
     * (8 + num_keys*(8 + PUB_KEY_LEN)) 
     */
    
    ran_file = fopen("/dev/urandom", "r");
    
    if(!ran_file){
        printf("[ERR] Server: Couldn't open urandom. Dropping transmission.\n");
        goto label_cleanup;
    }
    
    ret_val = fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file);
    
    if(ret_val != ONE_TIME_KEY_LEN){
        printf("[ERR] Server: Couldn't read urandom. Dropping transmission.\n");
        goto label_cleanup;
    }
    
    /* This function has already fetched and incremented the Nonce enough. */
    
    CHACHA20( send_K                               /* text: one-time key K    */
             ,ONE_TIME_KEY_LEN                     /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(LONG_NONCE_LEN / sizeof(u32))  /* Nonce_len in uint32_t's */
             ,(u32*)(KBA)                          /* chacha Key              */
             ,(u32)(SESSION_KEY_LEN / sizeof(u32)) /* Key_len in uint32_t's   */
             ,reply_buf + SMALL_FIELD_LEN          /* output target buffer    */
             );
    
    /* Increment nonce counter again to prepare the nonce for its next use. */
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    ++(clients[user_ix].nonce_counter); 
    
    *((u64*)(reply_buf + (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN))) 
     = num_users_in_room; 
    
    buf_ixs_pubkeys = calloc(1, buf_ixs_pubkeys_len);
    
    /* Iterate over all users in this chatroom, to grab their public keys. */
    buf_ixs_pubkeys_write_offset = 0;
    
    for(u64 i = 0; i < num_users_in_room; ++i){
    
        memcpy( buf_ixs_pubkeys + buf_ixs_pubkeys_write_offset
               ,clients[user_ixs_in_room[i]].user_id
               ,SMALL_FIELD_LEN
              );
        
        buf_ixs_pubkeys_write_offset += SMALL_FIELD_LEN;
              
        memcpy( buf_ixs_pubkeys + buf_ixs_pubkeys_write_offset
               ,clients[user_ixs_in_room[i]].client_pubkey.bits
               ,PUBKEY_LEN
              );
        
        buf_ixs_pubkeys_write_offset += PUBKEY_LEN;            
    }
    
    /* We need a counter for this ChaCha use, to encrypt big public keys. */
    
    CHACHA20( buf_ixs_pubkeys                      /* text - room people info */
             ,buf_ixs_pubkeys_len                  /* text_len in bytes       */
             ,(u32*)(nonce_bigint.bits)            /* Nonce                   */
             ,(u32)(SHORT_NONCE_LEN / sizeof(u32)) /* nonce_len in uint32_t's */
             ,(u32*)(send_K)                       /* chacha Key              */
             ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))/* Key_len in uint32_t's   */
             ,reply_buf + send_type20_AD_offset    /* output target buffer    */
             );
    
    /* Increment nonce counter again to prepare the nonce for its next use. */
    bigint_add_fast(&nonce_bigint, &one, &aux1);
    bigint_equate2(&nonce_bigint, &aux1);
    ++(clients[user_ix].nonce_counter); 
       
    send_type20_signed_len = (2 * SMALL_FIELD_LEN) 
                              + ONE_TIME_KEY_LEN 
                              + buf_ixs_pubkeys_len;
    
    Signature_GENERATE
        (M, Q, Gm, reply_buf, send_type20_signed_len
        ,reply_buf + send_type20_signed_len
        ,&server_privkey_bigint, PRIVKEY_LEN);
    
    /* The reply buffer is ready. Transmit it to the chatroom's new client. */  

    /* Reply to client with the user index and public key of all room guests. 
     * in encrypted form. The key to decrypt them itself is also encrypted
     * and hidden behind a deeper-level key extracted from the shared secret.
     */
    
    /*
    
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

    if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
        printf("[ERR] Server: Couldn't send Room-Join-OK message.\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Told client they were permitted in the room.\n");
    }
    
    printf("\n\n[OK]  Server: SUCCESS - Permitted a user in a chatroom!!\n\n");
    printf("Now to transmit the new user's public key to all room people!!\n");
    
    
    /* Add the new room guest's id and pubkey as a pending MSG to each user. */

    /* Construct the buffer before populating it into the users' structures. */
    
    /* Draw a random one-time use 32-byte key K, encrypt it with ChaCha20 using
     * KBA as chacha key and the server-client-maintained incremented Nonce from
     * the two's DH shared secret. Increment the Nonce. 
     *
     * Concatenate the encrypted one-time use key K, now KA, to PACKET_ID_2O.
     * Use un-encrypted key K as ChaCha key to encrypt the actual protected part
     * of the transmission to the clients, in this case:
     *
     *  (new_guest_userid, new_guest_public_key)
     *
     * whose length in bytes is exactly:
     *
     * (8 + PUB_KEY_LEN) 
     */
       
    for(u64 i = 0; i < num_users_in_room; ++i){
    
        /* Clear the reply buf to prepare it for next response by the server. */
        memset(buf_type_21, 0, buf_type_21_len);
       
        /* Place the network packet identifier 21 constant. */
        *((u64*)(buf_type_21)) = PACKET_ID_21;
        
        /* Draw the random one-time use 32-byte key K. */
        ret_val = fread(send_K, 1, ONE_TIME_KEY_LEN, ran_file);
    
        if(ret_val != ONE_TIME_KEY_LEN){
            printf("[ERR] Server: Couldn't read urandom. Dropping message.\n");
            goto label_cleanup;
        }
        
        /* Get session the keys KBA, KAB of this already-present room guest. */
        if(
           bigint_compare2( &(clients[user_ixs_in_room[i]].client_pubkey)
                           ,server_pubkey_bigint
           ) == 3
          )
        {
            memcpy( 
             KBA
            ,(clients[user_ixs_in_room[i]].shared_secret).bits
            ,SESSION_KEY_LEN
            );
            
            memcpy( 
             KAB
            ,(clients[user_ixs_in_room[i]].shared_secret).bits + SESSION_KEY_LEN
            ,SESSION_KEY_LEN
            );
        }
        else{
            /* KAB is FIRST 32 bytes of shared secret in this case, not next. */
            /* KBA is next 32 bytes. */   
            memcpy( 
             KAB
            ,(clients[user_ixs_in_room[i]].shared_secret).bits
            ,SESSION_KEY_LEN
            );
            
            memcpy( 
             KBA
            ,(clients[user_ixs_in_room[i]].shared_secret).bits + SESSION_KEY_LEN
            ,SESSION_KEY_LEN
            ); 
        }

        /* Another instance of BigInt constructor from mem. Find time for it. */
        /* MAX_BIGINT_SIZ is in bits, so divide by 8 to get the bytes.        */
        memset( nonce_bigint.bits
               ,0
               ,((size_t)((double)MAX_BIGINT_SIZ/(double)8))
        );
        
        memcpy( 
         nonce_bigint.bits
        ,clients[user_ixs_in_room[i]].shared_secret.bits + (2 * SESSION_KEY_LEN)
        ,LONG_NONCE_LEN
        ); 
          
        nonce_bigint.used_bits = 
            get_used_bits(nonce_bigint.bits, LONG_NONCE_LEN);
            
        nonce_bigint.size_bits = MAX_BIGINT_SIZ;
        nonce_bigint.free_bits = MAX_BIGINT_SIZ - nonce_bigint.used_bits;
       
        /* Increment nonce as many times as needed. */
        for(u64 j = 0; j < clients[user_ixs_in_room[i]].nonce_counter; ++j){
            bigint_add_fast(&nonce_bigint, &one, &aux1);
            bigint_equate2(&nonce_bigint, &aux1);     
        }

        CHACHA20(
            send_K                                  /* text - one-time key K  */
           ,ONE_TIME_KEY_LEN                        /* text_len in bytes      */
           ,(u32*)(nonce_bigint.bits)               /* Nonce                  */
           ,(u32)(LONG_NONCE_LEN / sizeof(u32))     /* nonce_len in uint32_ts */
           ,(u32*)(KBA)                             /* chacha Key             */
           ,(u32)(SESSION_KEY_LEN / sizeof(u32))    /* Key_len in uint32_t's  */
           ,buf_type_21 + SMALL_FIELD_LEN           /* output target buffer   */
        );
        
        /* Increment nonce counter again to prepare it for its next use. */
        bigint_add_fast(&nonce_bigint, &one, &aux1);
        bigint_equate2(&nonce_bigint, &aux1);
        ++(clients[user_ixs_in_room[i]].nonce_counter); 
        
        /* Place the part that has to be encrypted in a buffer. */

        memcpy( type21_encrypted_part
               ,clients[user_ix].user_id
               ,SMALL_FIELD_LEN
        );
        
        memcpy( type21_encrypted_part + SMALL_FIELD_LEN
               ,clients[user_ix].client_pubkey.bits
               ,PUBKEY_LEN
        );

        /* Encrypt it with chacha20, place the result ciphertext in response. */
        CHACHA20( 
         type21_encrypted_part                      /* text: user_ix + pubkey */
        ,(SMALL_FIELD_LEN + PUBKEY_LEN)             /* text_len in bytes      */
        ,(u32*)(nonce_bigint.bits)                  /* Nonce                  */
        ,(u32)(SHORT_NONCE_LEN / sizeof(u32))       /* nonce_len in uint32t's */
        ,(u32*)(send_K)                             /* chacha Key             */
        ,(u32)(ONE_TIME_KEY_LEN / sizeof(u32))      /* Key_len in uint32t's   */
        ,buf_type_21 + send_type21_encr_part_offset /* output target buffer   */
        );
        
        /* Increment nonce counter again to prepare it for its next use. */
        ++(clients[user_ixs_in_room[i]].nonce_counter); 
        
        /* Final part of TYPE_21 replies - signature itself. */
        /* Compute the signature itself of everything so far.*/
        
        Signature_GENERATE
        (     M, Q, Gm, buf_type_21
             ,buf_type_21_len - SIGNATURE_LEN
             ,buf_type_21 + (buf_type_21_len - SIGNATURE_LEN)
             ,&server_privkey_bigint
             ,PRIVKEY_LEN
        );
        
/* Send the new room guest's index and public key to all room participants.
 
    Server ----> Client
  
================================================================================
| packet ID 21 |        KC       | new_guest_ID | new_guest_PubKey | Signature |
|==============|=================|==============|==================|===========|
|  SMALL_LEN   | ONETIME_KEY_LEN |  SMALL_LEN   |    PUBKEY_LEN    |  SIG_LEN  |
--------------------------------------------------------------------------------

*/     
        add_pending_msg(user_ixs_in_room[i], buf_type_21_len, buf_type_21);
    }

label_cleanup:

    if(ran_file){ fclose(ran_file); }

    if(reply_buf)      { free(reply_buf);       }
    if(buf_ixs_pubkeys){ free(buf_ixs_pubkeys); }
 
    free(nonce_bigint.bits);
    free(one.bits);
    free(aux1.bits); 
    
    return;
}

/* A client requested to send a text message to everyone else in their chatroom.
 
 Client ----> Server
 
 Main packet structure:
 
================================================================================
| packetID 30 |  user_ix  |  TXT_LEN   |    AD   |          Signature1         | 
|=============|===========|============|=========|=============================|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN  | L bytes |            SIG_LEN          |
--------------------------------------------------------------------------------

 AD - Associated Data, of length L bytes: From T = 1 to num_guests:

================================================================================
| guestID_1 | encr_key_1 | encr_msg_1| ... |guestID_T | encr_key_T | encr_msg_T| 
|===========|============|===========|=====|==========|============|===========|
| SMALL_LEN |  X bytes   |  TXT_LEN  | ... |SMALL_LEN |  X bytes   |  TXT_LEN  |
--------------------------------------------------------------------------------

 L = (People in our chatroom - 1) * (SMALL_LEN + ONE_TIME_KEY_LEN + TXT_LEN)
 X = ONE_TIME_KEY_LEN

*/
void process_msg_30(u8* msg_buf, s64 packet_siz, u64 sign_offset, u64 sender_ix)
{
    u64 next_free_receivers_ix = 0;
    u64 reply_len = packet_siz + SIGNATURE_LEN;
    u64 signed_len = (packet_siz - SIGNATURE_LEN);
    u64 *receiver_ixs = NULL;

    char userid[SMALL_FIELD_LEN];

    u8 *reply_buf = NULL;

    memset(userid, 0, SMALL_FIELD_LEN);

    receiver_ixs = 
    calloc(1, (rooms[clients[sender_ix].room_ix].num_people -1) * sizeof(u64));

    reply_buf  = calloc(1, reply_len);

    /* Verify the sender's cryptographic signature. */
    if( authenticate_client(sender_ix, msg_buf, signed_len, sign_offset) != 1){
        printf("[ERR] Server: Invalid signature. Discarding transmission.\n\n");
        goto label_cleanup;
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }  
    
    /* Iterate over all user indices to find the other chatroom participants. */
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if(
              (clients[i].room_ix == clients[sender_ix].room_ix) 
            && 
              (i != sender_ix)
          )
        {
            receiver_ixs[next_free_receivers_ix] = i;
            ++next_free_receivers_ix;
        }
    }  
      
    /* Place the already received packet into the upgraded type_30 packet */
    memcpy(reply_buf, msg_buf, packet_siz);
        
    /* Compute the server's cryptographic signature of the entire received  
     * packet, including the sender's cryptographic signature!
     */
    
    Signature_GENERATE
                    (M, Q, Gm, reply_buf, packet_siz, (reply_buf + packet_siz)
                    ,&server_privkey_bigint, PRIVKEY_LEN
    );
        
    /* Replace the sender's index in the server's internal bookkeeping with
     * their userID so the client's internal bookkeeping can also locate them.
     */
    memcpy(userid, clients[sender_ix].user_id, SMALL_FIELD_LEN);

    memcpy(reply_buf + SMALL_FIELD_LEN, userid, SMALL_FIELD_LEN);

    /* Add upgraded type_30 packet to the intended receivers' pending MSGs. */
    /*
    
    Server ---> Client
    
================================================================================
| packetID 30 | sender_id |  TXT_LEN  |    AD   |     Sign1     |    Sign2     |  
|=============|===========|===========|=========|===============|==============|
|  SMALL_LEN  | SMALL_LEN | SMALL_LEN | L bytes |    SIG_LEN    |   SIG_LEN    |
--------------------------------------------------------------------------------    
    
    */
    for(u64 i = 0; i < rooms[clients[sender_ix].room_ix].num_people - 1; ++i){
        add_pending_msg(receiver_ixs[i], reply_len, reply_buf);
    }
    
label_cleanup:
    
    free(reply_buf);
    free(receiver_ixs);
    
    return;
}

/* A client polled the server for any pending unreceived messages.
 
 Client ----> Server
  
================================================================================
| packet ID 40 |  user_ix  |                    SIGNATURE                      | 
|==============|===========|===================================================|
|  SMALL_LEN   | SMALL_LEN |                     SIG_LEN                       |
--------------------------------------------------------------------------------

*/
void process_msg_40(u8* msg_buf, u32 sock_ix){
        
    u8 *reply_buf = NULL;

    u64 reply_len;
    u64 reply_write_offset = 0;
    u64 sign_offset = 2 * SMALL_FIELD_LEN;
    u64 signed_len = sign_offset;
    u64 poller_ix = *((u64*)(msg_buf + SMALL_FIELD_LEN));
    
    /* Verify the sender's cryptographic signature to make sure they're legit */
    if( authenticate_client(poller_ix, msg_buf, signed_len, sign_offset) != 1 ){
        printf("[ERR] Server: Invalid signature. Discrading transmission.\n\n");
        goto label_cleanup;       
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }
    
    clients[poller_ix].time_last_polled = clock();
    
    /* If no pending messages, simply send the NO_PENDING packet type_40. */
    if(clients[poller_ix].num_pending_msgs == 0){
    
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        
        *((u64*)(reply_buf)) = PACKET_ID_40;
        
        /* Compute a cryptographic signature so the client can authenticate us*/
        Signature_GENERATE
             ( M, Q, Gm, reply_buf, SMALL_FIELD_LEN, reply_buf + SMALL_FIELD_LEN
              ,&server_privkey_bigint, PRIVKEY_LEN
        );
        
/*

 No pending messages for the polling client were found.
 
 Server ----> Client
  
================================================================================
| packet ID 40 |                         SIGNATURE                             | 
|==============|===============================================================|
|  SMALL_LEN   |                          SIG_LEN                              |
--------------------------------------------------------------------------------

*/        
        /* Send the reply back to the client. */
        if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
            printf("[ERR] Server: Couldn't reply with PACKET_ID_40 message.\n");
        }
        else{
            printf("[OK]  Server: Replied with PACKET_ID_40 message.\n");
        }
        
        goto label_cleanup;
    }
    /* If there are pending messages, construct a buffer containing them all. */
    else{
    
        /* We need to allocate enough memory for the reply buffer. This can only
         * happen if we preemptively iterate over the sender's array of lengths
         * of pending messages, even if we will need to do it again later to 
         * actually fetch their pending messages.
         */
        reply_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        reply_write_offset = 2 * SMALL_FIELD_LEN;
        
        for(u64 i = 0; i < clients[poller_ix].num_pending_msgs; ++i){
         reply_len += clients[poller_ix].pending_msg_sizes[i] + SMALL_FIELD_LEN;    
        } 
         
        reply_buf = calloc(1, reply_len);
                
        *((u64*)(reply_buf)) = PACKET_ID_41;
        *((u64*)(reply_buf + SMALL_FIELD_LEN)) = 
                                            clients[poller_ix].num_pending_msgs;
        
        /* Iterate over this client's array of pending transmissions, as well */
        /* as their array of lengths to transport them to the reply buffer.   */
        for(u64 i = 0; i < clients[poller_ix].num_pending_msgs; ++i){
            
            *((u64*)(reply_buf + reply_write_offset)) 
             = clients[poller_ix].pending_msg_sizes[i];
                             
            reply_write_offset += SMALL_FIELD_LEN;
                   
            memcpy( reply_buf + reply_write_offset
                   ,clients[poller_ix].pending_msgs[i] 
                   ,clients[poller_ix].pending_msg_sizes[i] 
            );
                 
            reply_write_offset += clients[poller_ix].pending_msg_sizes[i];
            
            clients[poller_ix].pending_msg_sizes[i] = 0;
            
            memset( clients[poller_ix].pending_msgs[i]
                   ,0
                   ,clients[poller_ix].pending_msg_sizes[i] 
            );
        }

        /* Compute a cryptographic signature so the client can authenticate us*/
        Signature_GENERATE
                         ( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN, 
                           reply_buf + (reply_len - SIGNATURE_LEN)
                          ,&server_privkey_bigint, PRIVKEY_LEN
        );
        
        clients[poller_ix].num_pending_msgs = 0;
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
        /* Send the reply back to the client. */
        if(send(client_socket_fd[sock_ix], reply_buf, reply_len, 0) == -1){
            printf("[ERR] Server: Couldn't reply with PACKET_ID_41 msg.\n");
        }
        else{
            printf("[OK]  Server: Replied to client with PACKET_ID_41 msg.\n");
        }
        
        goto label_cleanup;
    }
  
label_cleanup:

    if(reply_buf){
        free(reply_buf);
    }
    
    return;
}

/* A client decided to leave the chatroom they're currently in. */
void process_msg_50(u8* msg_buf){
    
    u64 sign_offset = 2 * SMALL_FIELD_LEN;
    u64 signed_len = sign_offset;
    u64 sender_ix = *((u64*)(msg_buf + SMALL_FIELD_LEN));

    /* Verify the sender's cryptographic signature to make sure they're legit */
    if( authenticate_client(sender_ix, msg_buf, signed_len, sign_offset) != 1 ){
        printf("[ERR] Server: Invalid signature. Discrading transmission.\n\n");
        return;      
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }
 
    remove_user_from_room(sender_ix);

    return;
}

/* A client decided to log off Rosetta. */
void process_msg_60(u8* msg_buf){
  
    u64 sign_offset = 2 * SMALL_FIELD_LEN;
    u64 signed_len  = sign_offset;
    u64 sender_ix   = *((u64*)(msg_buf + SMALL_FIELD_LEN));
    
    /* Verify the sender's cryptographic signature to make sure they're legit */
    if( authenticate_client(sender_ix, msg_buf, signed_len, sign_offset) != 1 ){
        printf("[ERR] Server: Invalid signature. Discrading transmission.\n\n");
        return;     
    }
    else{
        printf("[OK]  Server: Client authenticated successfully!\n");
    }

    /* Clear the user descriptor structure and alter the global index array. */
    memset(&(clients[sender_ix]), 0, sizeof(struct connected_client));
    
    users_status_bitmask &= ~(1ULL << (63ULL - sender_ix));

    return;
}

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
u32 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u32 sock_ix){

    printf("?? identifier entering?? \n");

    u64 transmission_type = 0;
    u64 found_user_ix;
    u64 text_msg_len;

    s64 expected_siz = 0;

    u32 ret_val = 0;

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
            ret_val = 1;
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
            ret_val = 1;
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
            ret_val = 1;
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
            ret_val = 1;
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
         
        found_user_ix = *((u64*)(client_msg_buf + SMALL_FIELD_LEN));
        text_msg_len  = *((u64*)(client_msg_buf + (2 * SMALL_FIELD_LEN)));

        expected_siz =   (3 * SMALL_FIELD_LEN)
                       + ( 
                          (rooms[clients[found_user_ix].room_ix].num_people - 1)
                          *
                          (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len)
                         ) 
                       + *((u64*)(client_msg_buf + (2 * SMALL_FIELD_LEN)))
                       + SIGNATURE_LEN;
                    
        if(bytes_read != expected_siz){
            ret_val = 1;
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
            ret_val = 1;
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
            ret_val = 1;
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
            ret_val = 1;
            goto label_error;
        }
        
        /* If transmission is of a valid type and size, process it. */
        process_msg_60(client_msg_buf);
        
        break;            
    
    }
    
    /* Also do something in case it was a bad unrecognized transmission.  */
    /* Just say FUCK YOU to whoever sent it and perhaps tried hacking us. */
    default:{
        printf("[WAR] Server: No valid packet type found in request.\n\n");
        /* Send the reply back to the client. */
        if(send(client_socket_fd[sock_ix], "fuck you", 8, 0) == -1){
            printf("[ERR] Server: Couldn't reply to a bad transmission.\n");
            ret_val = 1;
            goto label_error;
        }
        else{
            printf("[OK]  Server: Replied to a bad transmission.\n");
        }    
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
    
    return ret_val;
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

        printf( "\n[OK] Server: Detector of lost connections STARTED: %s\n"
               ,ctime(&curr_time)
        );
        
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
               (difftime(curr_time, clients[i].time_last_polled) > 20.0)
              )
            {
                printf("[ERR] Server: Caught an inactive connected client!\n"
                       "              Removing them from the server:\n"
                       "              user_slot_bitmask_ix: [%lu]\n"
                       "              this_user's_room_ix : [%lu]\n"
                       "              Time since last poll: %lf seconds\n\n"
                       ,i
                       ,clients[i].room_ix
                       ,difftime(curr_time, clients[i].time_last_polled)
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
         * transport the cl\n\n", bytes_read);he failed login attempt and unlock it from here.
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

        printf( "\n[OK] Server: Detector of lost connections ENDED: %s\n"
               ,ctime(&curr_time)
        );
        
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

int main(){

    u32 status;
    u32 curr_free_socket_ix;

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




