#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cryptolib.h"
#include "bigint.h"

#define SERVER_PORT    54746
#define PRIVKEY_BYTES  40   
#define MAX_CLIENTS    64
#define MAX_PEND_MSGS  1024
#define MAX_CHATROOMS  64
#define MAX_MSG_LEN    1024
#define MAX_SOCK_QUEUE 1024
#define MAX_BIGINT_SIZ 12800

#define MAGIC_0_RECV      0xAD0084FF0CC25B0E
#define MAGIC_0_SEND_NO  0x7
#define MAGIC_0_SEND_OK  
#define MAGIC_1          0xE7D09F1FEFEA708B

/* Cryptography, users and chatroom related globals. */

/* A bitmask telling the server which client slots are currently free.   */
uint64_t clients_status_bitmask = 0;

uint32_t next_free_user_ix = 0;
uint32_t next_free_room_ix = 1;

uint8_t server_privkey[PRIVKEY_BYTES];

uint32_t signature_siz = (2 * sizeof(struct bigint)) + (2 * PRIVKEY_BYTES);

struct connected_client{
    uint32_t room_ix;
    uint32_t num_pending_msgs;
    uint8_t* pending_msgs[MAX_PEND_MSGS];
    uint8_t* client_pubkey;
    uint64_t pubkey_siz_bytes;
};

struct chatroom{
    uint32_t num_people;
    uint32_t owner_ix;
    char*    room_name;
}

struct connected_client clients[MAX_CLIENTS];
struct chatroom rooms[MAX_CHATROOMS];


/* Linux Sockets API related globals. */

int    port = SERVER_PORT
   ,listening_socket
   ,optval1 = 1
   ,optval2 = 2
   ,client_socket_fd;
      
socklen_t clientLen = sizeof(struct sockaddr_in);

struct bigint      *M, *Q, *G, *Gm, server_privkey_bigint;
struct sockaddr_in client_address;
struct sockaddr_in server_address;

/* First thing done when we start the server - initialize it. */
uint32_t self_init(){

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

uint8_t check_pubkey_exists(uint8_t* pubkey_buf, uint64_t pubkey_siz){

    if(pubkey_siz < 300){
        printf("\n[WARN] Server: Passed a small PubKey Size: %u\n", pubkey_siz);
        return 2;
    }

    /* client slot has to be taken, size has to match, then pubkey can match. */
    for(uint64_t i = 0; i < MAX_CLIENTS; ++i){
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

uint32_t process_new_message(){

    uint8_t* client_message_buf = calloc(1, MAX_MSG_LEN);
    int64_t  bytes_read; 
    uint64_t transmission_type;
    uint64_t expected_siz;
    uint8_t* reply_buf;
    uint8_t* reply_text;
    size_t      reply_len;
    
    /* Capture the message the Rosetta TCP client sent to us. */
    bytes_read = recv(client_socket, client_message_buf, MAX_MSG_LEN, 0);
    
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
    
    /* A clear definition of possible TCP messages is needed. Examples:
     *
     * - a user sent a text message in their chatroom
     * - a user's client polled us for any pending messages for them.
     * - a user wants to create their own new chatroom
     * - a user wants to enter an existing chatroom
     * - a user wants to leave a chatroom they're NOT the owner of. 
     * - a user wants to leave a chatroom which they're the owner of. 
     * - a user simply initialized connection with the TCP server.
     *
     */
     
    /* Read the first 8 bytes to see what type of transmission it is. */
    transmission_type = *((uint64_t*)client_message_buf);
    
    switch(transmission_type){
    
    /* A client tried to log in Rosetta, initialize the connection. */
    case(MAGIC_0){
    
        /* Size must be in bytes: 8 + 8 + pubkeysiz, which is bytes[8-15] */
        expected_siz = (16 + (*((uint64_t*)(client_message_buf + 8))));
        
        if(bytes_read != expected_siz){
            printf("[WARN] Server: MSG Type was 0 but of wrong size.\n");
            printf("               Size was: %ld\n", bytes_read);
            printf("               Expected: %lu\n", expected_siz);
            printf("\n[OK] Discarding transmission.\n\n ");
            return 1;
        }
        
        /* Create the new user structure instance with the public key. */
        
        /* A message arrived to permit a newly arrived user to use Rosetta, but
         * currently the maximum number of clients are using it. Try later.
         */
        if(next_free_user_ix == MAX_CLIENTS){
            printf("[WARN] - Not enough client slots to let a user in.\n");
            printf("         Letting the user know and to try later.  \n");
            
            /* Let the user know that Rosetta is full right now, try later. */
            reply_text = "Rosetta is full, try later";
            reply_len  = strlen(strcat(reply_text, "\0")) + signature_siz;
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
               (client_message_buf + 16), *((uint64_t*)(client_message_buf + 8))
             ) > 0
          )
        {
            printf("[WARN] Server: Obtained public key was BAD for MSG 0.\n");
            printf("\n[OK] Discarding transmission.\n");
            return 1;
        }
        
        reply_buf = calloc(1, 4 + signature_siz);
        
        memcpy(reply_buf, &next_free_user_ix, 4); 
        
        clients[next_free_user_ix].room_ix = 0;
        clients[next_free_user_ix].num_pending_msgs = 0;
    
        for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
            clients[next_free_user_ix].pending_msgs[i] = calloc(1, MAX_MSG_LEN);
        }
        
        clients[next_free_user_ix].pubkey_siz_bytes 
         = (*((uint64_t*)(client_message_buf + 8)));
    
    
        clients[next_free_user_ix].client_pubkey 
         = 
         calloc(1, clients[next_free_user_ix].pubkey_siz_bytes);
         
        memcpy(  clients[next_free_user_ix].client_pubkey 
                 ,(client_message_buf + 16)
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
        
        if(send(client_socket, reply_buf, (4 + signature_siz), 0) == -1){
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


int main(){
    
    /* Initialize Sockets API, load own private key. */ 
    self_init();

    uint32_t status;
    
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
