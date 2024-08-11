#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cryptolib.h"
#include "coreutil.h"

#define SERVER_PORT    54746
#define PRIVKEY_BYTES  40   
#define PUBKEY_BYTES   384
#define MAX_CLIENTS    64
#define MAX_PEND_MSGS  1024
#define MAX_CHATROOMS  64
#define MAX_MSG_LEN    1024
#define MAX_SOCK_QUEUE 1024
#define MAX_BIGINT_SIZ 12800
#define MAGIC_LEN      8 

#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_BYTES))
#define TEMP_BUF_SIZ   ((4 * sizeof(bigint)) + (3 * 32) + 12)

#define MAGIC_00 0xAD0084FF0CC25B0E
#define MAGIC_01 0xE7D09F1FEFEA708B


/* A bitmask for various control-related purposes.
 * 
 * Currently used bits:
 *
 *  [0] - Whether the temporary login handshake memory region is locked or not.
 *        This memory region holds very short-term public/private keys used
 *        to transport the client's long-term public key to us securely.
 *        It can't be local, because the handshake spans several transmissions,
 *        (thus is interruptable) yet needs the keys for its entire duration.
 *        Every login procedure needs it. If a second client attempts to login
 *        while another client is already logging in, without checking this bit,
 *        the other client's login procedure's short-term keys could be erased.
 *        Thus, use this bit to disallow more than 1 login handshake at a time.
 *
 */ 
u32 server_control_bitmask = 0;


/* A bitmask telling the server which client slots are currently free.   */
u64 clients_status_bitmask = 0;


u32 next_free_user_ix = 0;
u32 next_free_room_ix = 1;

u8 server_privkey[PRIVKEY_BYTES];



struct connected_client{
    u32 room_ix;
    u32 num_pending_msgs;
    u8* pending_msgs[MAX_PEND_MSGS];
    u8* client_pubkey;
    u64 pubkey_siz_bytes;
};

struct chatroom{
    u32 num_people;
    u32 owner_ix;
    char*    room_name;
}

struct connected_client clients[MAX_CLIENTS];
struct chatroom rooms[MAX_CHATROOMS];


/* Memory region holding the temporary keys for the login handshake. */
u8* temp_handshake_buf;

/* Linux Sockets API related globals. */

int port = SERVER_PORT
   ,listening_socket
   ,optval1 = 1
   ,optval2 = 2
   ,client_socket_fd;
      
socklen_t clientLen = sizeof(struct sockaddr_in);

struct bigint *M, *Q, *G, *Gm, server_privkey_bigint;
struct sockaddr_in client_address;
struct sockaddr_in server_address;

/* First thing done when we start the server - initialize it. */
u32 self_init(){

    /* Allocate memory for the global login handshake memory region. */
    temp_handshake_buf = calloc(1, TEMP_BUF_SIZ);

    server_address = {  .sin_family = AF_INET
                       ,.sin_port = htons(port)
                       ,.sin_addr.s_addr = INADDR_ANY
                     };
                                                 
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
                      
    if( 
       (
        bind(
            listening_socket
           ,(struct sockaddr*)&server_address
           ,sizeof(server_address)
        )
       ) == -1
      )
      {
        if(errno != 13){
            printf("[ERR] Server: bind() failed. Errno != 13. Aborting.\n");
            return 1;
        }
      }
       
    if( (listen(listening_socket, MAX_SOCK_QUEUE)) == -1){
        printf("[ERR] Server: couldn't begin listening. Aborting.\n");
        return 1;
    }
    
    
    /*  Server will use its private key to compute Schnorr signatures of 
     *  everything it transmits, so all users can verify it with the server's
     *  public key they already have by default for authenticity.
     */
    FILE* privkey_dat = fopen("server_privkey.dat", "r");
    
    if(!privkey_dat){
        printf("[ERR] Server: couldn't open private key DAT file. Aborting.\n");
        return 1;
    }
    
    if(fread(server_privkey, 1, PRIVKEY_BYTES, privkey_dat) != PRIVKEY_BYTES){
        printf("[ERR] Server: couldn't get private key from file. Aborting.\n");
        return 1;
    }
    else{
        printf("[OK] Server: Successfully loaded private key.\n");
    }
    
    /* Initialize the BigInt that stores the server's private key. */
    bigint_create(&server_privkey_bigint, MAX_BIGINT_SIZ, 0);
    
    memcpy(server_privkey_bigint.bits, server_privkey, PRIVKEY_BYTES); 
    
    server_privkey_bigint.used_bits = 
                            get_used_bits(server_privkey, PRIVKEY_BYTES);
                            
    server_privkey_bigint.free_bits = 
                            MAX_BIGINT_SIZ - server_privkey_bigint.used_bits;
            
    /* Load in other BigInts needed for the cryptography to work. */
    
    /* Diffie-Hellman modulus M, 3071-bit prime number */                        
    M = get_BIGINT_from_DAT
        (3072, "../saved_nums/M_raw_bytes.dat\0", 3071, RESBITS);
    
    /* 320-bit prime exactly dividing M-1, making M cryptographycally strong. */
    Q = get_BIGINT_from_DAT
        (320,  "../saved_nums/Q_raw_bytes.dat\0", 320,  RESBITS);
    
    /* Diffie-Hellman generator G = G = 2^((M-1)/Q) */
    G = get_BIGINT_from_DAT
        (3072, "../saved_nums/G_raw_bytes.dat\0", 3071, RESBITS);

    /* Montgomery Form of G, since we use Montgomery Multiplication. */
    Gm = get_BIGINT_from_DAT
        (3072, "../saved_nums/PRACTICAL_Gmont_raw_bytes.dat\0", 3071, RESBITS);
    
    fclose(privkey_dat);
    
    return 0;
}

u8 check_pubkey_exists(u8* pubkey_buf, u64 pubkey_siz){

    if(pubkey_siz < 300){
        printf("\n[WARN] Server: Passed a small PubKey Size: %u\n", pubkey_siz);
        return 2;
    }

    /* client slot has to be taken, size has to match, then pubkey can match. */
    for(u64 i = 0; i < MAX_CLIENTS; ++i){
        if(   (clients_status_bitmask & (1ULL << (63ULL - i)))
           && (clients[i].pubkey_siz_bytes == pubkey_siz)
           && (memcmp(pubkey_buf, clients[i].client_pubkey, pubkey_siz) == 0)
          )
        {
            printf("\n[WARN] Server: PubKey already exists.\n\n");
            return 1;
        }
    }
    
    return 0;
}


__attribute__ ((always_inline)) 
inline
void process_msg_01(u8* msg_buf){

    bigint *A_s
          ,zero
          ,Am
          ,*b_s
          ,*B_s
          ,*X_s;
            
    u32  *KAB_s
        ,*KBA_s
        ,*Y_s
        ,*N_s
        ,tempbuf_byte_offset = 0;
        
    u8 *signature_buf = calloc(1, SIGNATURE_LEN);
            
    u8* reply_buf;
    u64 reply_len;

    /* Construct a bigint out of the client's short-term public key.          */
    /* Here's where a constructor from a memory buffer and its length is good */
    /* Find time to implement one as part of the BigInt library.              */
    
    /* Allocate any short-term keys and other cryptographic artifacts needed for
     * the initial login handshake protocol in the designated memory region and
     * lock it, disallowing another parallel login attempt to corrupt them.
     */
    server_control_bitmask |= (1ULL << 63ULL);
    
    A_s = temp_handshake_buf;
    A_s->bits = calloc(1, MAX_BIGINT_SIZ);
    memcpy(A_s->bits, msg_buf + 16, *(msg_buf + 8));
    A_s->bits_size = MAX_BIGINT_SIZ;
    A_s->used_bits = get_used_bits(msg_buf + 16, (u32)*(msg_buf + 8));
    A_s->free_bits = A_s->bits_size - A_s->used_bits;
    
    /* Check that (0 < A_s < M) and that (A_s^(M/Q) mod M = 1) */
    
    /* A "check non zero" function in the BigInt library would also be useful */
    
    bigint_create(&zero, MAX_BIGINT_SIZ, 0);
    
    Get_Mont_Form(A_s, &Am, M);
    
    if(   ((bigint_compare2(&zero, A_s)) != 3) 
        || 
          ((bigint_compare2(M, A_s)) != 1)
        ||
          (check_pubkey_form(Am, M, Q) == 0) 
      )
    {
        printf("[ERR] Server: Client's short-term public key is invalid.\n");
        printf("\n\nIts info and ALL bits:\n\n");
        bigint_print_info(A_s);
        bigint_print_all_bits(A_s);
        goto label_cleanup;
    } 
    
    /*  Server generates its own short-term DH keys and a shared secret X:
     *    
     *       b_s = random in the range [1, Q)
     * 
     *       B_s = G^b_s mod M     <--- Montgomery Form of G used.
     *   
     *       X_s = A_s^b_s mod M   <--- Montgomery Form of A_s used.
     *
     *  Server extracts two keys and two values Y, N from byte regions in X:
     *
     *       KAB_s = X_s[0  .. 31 ]
     *       KBA_s = X_s[32 .. 63 ]
     *       Y_s   = X_s[64 .. 95 ]
     *       N_s   = X_s[96 .. 107] <-- 12-byte Nonce for ChaCha20.
     *
     *  These 7 things are all stored in the designated locked memory region.
     */

    gen_priv_key(PRIVKEY_BYTES, (temp_handshake_buf + sizeof(bigint)));
    
    b_s = *(temp_handshake_buf + sizeof(bigint));
    
    /* Interface generating a pub_key still needs priv_key in a file. Change. */
    save_BIGINT_to_DAT("temp_privkey_DAT\0", b_s);
  
    B_s = gen_pub_key(PRIVKEY_BYTES, "temp_privkey_DAT\0", MAX_BIGINT_SIZ);
    
    /* Place the server short-term pub_key also in the locked memory region. */
    memcpy((temp_handshake_buf + (2 * sizeof(bigint))), B_s, sizeof(bigint));
    
    /* X_s = A_s^b_s mod M */
    X_s = temp_handshake_buf + (3 * sizeof(bigint));
    
    bigint_create(X_s, MAX_BIGINT_SIZ, 0);
    
    MONT_POW_modM(Am, b_s, M, X_s);
    
    /* Extract KAB_s, KBA_s, Y_s and N_s into the locked memory region. */
    tempbuf_byte_offset = 4 * sizeof(bigint);
    memcpy(temp_handshake_buf + tempbuf_byte_offset, X_s->bits +  0, 32);
    KAB_s = (u32*)(temp_handshake_buf + tempbuf_byte_offset);
    
    tempbuf_byte_offset += 32;
    memcpy(temp_handshake_buf + tempbuf_byte_offset, X_s->bits + 32, 32);
    KBA_s = (u32*)(temp_handshake_buf + tempbuf_byte_offset);
    
    tempbuf_byte_offset += 32;
    memcpy(temp_handshake_buf + tempbuf_byte_offset, X_s->bits + 64, 32);
    Y_s = temp_handshake_buf + tempbuf_byte_offset;
        
    tempbuf_byte_offset += 32;
    memcpy(temp_handshake_buf + tempbuf_byte_offset, X_s->bits + 96, 12);
    N_s = temp_handshake_buf + tempbuf_byte_offset;
    
    /*  Compute a signature of Y_s using LONG-TERM private key b, yielding SB. */
    Signature_GENERATE
      (M, Q, Gm, Y_s, 32, signature_buf, &server_privkey_bigint, PRIVKEY_BYTES);
                  
    /* Server sends in the clear (B_s, SB) to the client. */
    
    /* Find time to change the signature generation to only place the actual
     * bits of s and e, excluding their bigint structs, because we reconstruct
     * their bigint structs easily with get_used_bits().
     */
    
    /* Construct the reply buffer. */
    reply_len = MAGIC_LEN + SIGNATURE_LEN + PUBKEY_BYTES;
    reply_buf = calloc(1, reply_len);
    
    *((u64*)(reply_buf + 0)) = MAGIC_00;
    
    memcpy(reply_buf + MAGIC_LEN, B_s->bits, PUBKEY_BYTES);
    memcpy(reply_buf + MAGIC_LEN + PUBKEY_BYTES, signature_buf, SIGNATURE_LEN);
    
    /* Send the reply back to the client. */
    if(send(client_socket, reply_buf, reply_len, 0) == -1){
        printf("[ERR] Server: Couldn't reply with MAGIC_00 msg type.\n");
    }
    else{
        printf("[OK] Server: Replied to client with MAGIC_00 msg type.\n");
    }
    
    return;
  
label_cleanup: 
  
    free(zero.bits);
    free(Am.bits);
    free(signature_buf);
    free(reply_buf);
    /* Do NOT free A_s's bits yet, they'll be needed in the processor of the 
     * other transmission that's part of the login handshake protocol. 
     */
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
 *      - A client decides to log in Rosetta:
 *
 *          - [TYPE_00]: Client sent its short-term pub_key in the clear.
 *          - [TYPE_01]: Client sent encrypted long-term pub_key + 8-byte HMAC
 *
 *      - A client decides to join a chat room.
 *      - A client decides to make a new chat room.
 *      - A client decides to send a new message to the chatroom.
 *      - A client decides to poll the server about unreceived messages.
 *      - A client decides to exit the chat room they're in.
 *      - A client decides to log off Rosetta.
 */

u32 process_new_message(){

    u8* client_msg_buf = calloc(1, MAX_MSG_LEN);
    s64 bytes_read; 
    u64 transmission_type;
    u64 expected_siz;
    u8* reply_buf;
    u8* reply_text;
    u64 reply_len;
    
    /* Capture the message the Rosetta TCP client sent to us. */
    bytes_read = recv(client_socket, client_msg_buf, MAX_MSG_LEN, 0);
    
    if(bytes_read == -1 || bytes_read < 8){
        printf("[ERR] Server: Couldn't read message on socket or too short.\n");
        return 1;
    }
    else{
        printf( "[OK] Server: Just read %u bytes from a received message!\n\n"
               ,bytes_read
        );
    }
    
    /* Examine the message and react to it accordingly. */
       
    /* Read the first 8 bytes to see what type of init transmission it is. */
    transmission_type = *((u64*)client_msg_buf);
    
    switch(transmission_type){
    
    /* A client tried to log in Rosetta, initialize the connection. */
    case(MAGIC_00){
    
        /* Size must be in bytes: 8 + 8 + pubkeysiz, which is bytes[8-15] */
        expected_siz = (16 + (*((u64*)(client_msg_buf + 8))));
        
        if(bytes_read != expected_siz){
            printf("[WARN] Server: MSG Type was 0 but of wrong size.\n");
            printf("               Size was: %ld\n", bytes_read);
            printf("               Expected: %lu\n", expected_siz);
            printf("\n[OK] Discarding transmission.\n\n ");
            return 1;
        }
        
        
       process_msg_01(client_msg_buf);
       
        
        /* NONE OF THIS IS EVEN A REACTION TO MSG_00 ANYMORE!!! */
        /* MOVE IT TO THE REACTION FUNCTION TO MSG_01 ASAP!!!   */
        
        /* Create the new user structure instance with the public key. */
        
        /* A message arrived to permit a newly arrived user to use Rosetta, but
         * currently the maximum number of clients are using it. Try later.
         */
        if(next_free_user_ix == MAX_CLIENTS){
            printf("[WARN] - Not enough client slots to let a user in.\n");
            printf("         Letting the user know and to try later.  \n");
            
            /* Let the user know that Rosetta is full right now, try later. */
            reply_text = "Rosetta is full, try later";
            reply_len  = strlen(strcat(reply_text, "\0")) + SIGNATURE_LEN;
            reply_buf  = calloc(1, reply_len);
        
            /**********  KEEP CHANGING HERE ***************/
            /* BUT LOOK AT NEW INITIAL HANDSHAKE SCHEME WITH KAB */
            memcpy(reply_buf, &next_free_user_ix, 4); 
            
            if(send(client_socket, reply_buf, reply_len, 0) == -1){
                printf("[ERR] Server: Couldn't send full-rosetta message.\n");
            }
            else{
                printf("[OK] Server: Told client Rosetta is full, try later\n");
            }
            return 1;
        }
        
        if(  check_pubkey_exists(
               (client_msg_buf + 16), *((u64*)(client_msg_buf + 8))
             ) > 0
          )
        {
            printf("[WARN] Server: Obtained public key was BAD for MSG 0.\n");
            printf("\n[OK] Discarding transmission.\n");
            return 1;
        }
        
        reply_buf = calloc(1, 4 + SIGNATURE_LEN);
        
        memcpy(reply_buf, &next_free_user_ix, 4); 
        
        clients[next_free_user_ix].room_ix = 0;
        clients[next_free_user_ix].num_pending_msgs = 0;
    
        for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
            clients[next_free_user_ix].pending_msgs[i] = calloc(1, MAX_MSG_LEN);
        }
        
        clients[next_free_user_ix].pubkey_siz_bytes 
         = (*((u64*)(client_msg_buf + 8)));
    
    
        clients[next_free_user_ix].client_pubkey 
         = 
         calloc(1, clients[next_free_user_ix].pubkey_siz_bytes);
         
        memcpy(  clients[next_free_user_ix].client_pubkey 
                 ,(client_msg_buf + 16)
                 ,clients[next_free_user_ix].pubkey_siz_bytes
               );
        
        /* Reflect the new taken user slot in the global user status bitmask. */
        clients_status_bitmask |= (1ULL << (63ULL - next_free_user_ix));
        
        /* Increment it one space to the right, since we're guaranteeing by
         * logic in the user erause algorithm that we're always filling in
         * a new user in the leftmost possible empty slot.
         *
         * If you're less than (max_users), look at this slot and to the right
         * in the bitmask for the next leftmost empty user slot index. If you're
         * equal to (max_users) then the maximum number of users are currently
         * using Rosetta. Can't let any more people in until one leaves.
         *
         * Here you either reach MAX_CLIENTS, which on the next attempt to 
         * let a user in and fill out a user struct for them, will indicate
         * that the maximum number of people are currently using Rosetta, or
         * you reach a bit at an index less than MAX_CLIENTS that is 0 in the
         * global user slots status bitmask.
         */
        ++next_free_user_ix;
        
        while(next_free_user_ix < MAX_CLIENTS){
            if(!(clients_status_bitmask & (1ULL<<(63ULL - next_free_user_ix))))
            {
                break;
            }
            ++next_free_user_ix;
        }
        
        printf("\n\nServer: Calling Signature_GENERATE() NOW!!!\n\n");
        
        Signature_GENERATE(  M, Q, Gm, reply_buf, 4, (reply_buf + 4),
                             server_privkey_bigint, PRIVKEY_BYTES
                          );
                      
        printf("Server: FINISHED SIGNATURE!!\n");
        printf("Server: Resulting signature itself is (s,e) both BigInts.\n");
        printf("Server: It was placed in reply_buf[4+].\n");
        
        if(send(client_socket, reply_buf, (4 + SIGNATURE_LEN), 0) == -1){
            printf("[ERR] Server: Couldn't send init-OK message.\n");
            return 1;
        }
        else{
            printf("[OK] Server: Told client initialization went OK.\n");
        }
        
        printf("\n\n[OK] Successfully permitted a new user in Rosetta!!\n\n");
        
        return 0;

    }
    
    /* Join Room */
    case(MAGIC_1){
                    
    }
    
    } /* end switch */
    
    
    /* FREE EVERYTHING THIS FUNCTION ALLOCATED */
    free();
}
int main(){
    
    /* Initialize Sockets API, load own private key. */ 
    self_init();

    u32 status;
    
    while(1){
    
        /* Block on this accept() call until someone sends us a message. */
        client_socket_fd = accept(  server_socket
                                      ,(struct sockaddr*)(&client_address)
                                      ,&clientLen
                                   );
                                   
        /* 0 on success, greater than 0 otherwise. */                         
        status = process_new_message();
        
        if(status){
            printf("\n\n****** WARNING ******\n\n"
                   "Error while processing a received "
                   "transmission, look at log to find it.\n"
                  );    
        }
                              
    }
                

    /* Does it really matter to free() it? Not like the heap space is gonna
     * be used for anything else at this point, as the server is about to
     * be shut down. Do it anyway for completeness.
     */
     
    free(client_message);
    
    return 0;
}
