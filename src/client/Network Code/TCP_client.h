#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/coreutil.h"

#define SERVER_PORT      54746
#define PRIVKEY_LEN      40   
#define PUBKEY_LEN       384
#define MAX_CLIENTS      64
#define MAX_PEND_MSGS    64
#define MAX_CHATROOMS    64
#define MAX_MSG_LEN      8192
#define MAX_TXT_LEN      1024
#define MAX_SOCK_QUEUE   1024
#define MAX_BIGINT_SIZ   12800
#define SMALL_FIELD_LEN  8 
#define MAX_USERID_CHARS 8
#define TEMP_BUF_SIZ     16384
#define SESSION_KEY_LEN  32
#define ONE_TIME_KEY_LEN 32
#define INIT_AUTH_LEN    32
#define SHORT_NONCE_LEN  12
#define LONG_NONCE_LEN   16
#define HMAC_TRUNC_BYTES 8

#define SIGNATURE_LEN  ((2 * sizeof(bigint)) + (2 * PRIVKEY_LEN))

struct roommate{
    char   user_id[MAX_USERID_CHARS];
    u64    client_nonce_counter;
    bigint client_pubkey;
    bigint client_pubkey_mont;
    bigint client_shared_secret; 
};

u64  own_ix = 0;
char own_user_id[MAX_USERID_CHARS];

bigint server_shared_secret;
u64    server_nonce_counter;

pthread_mutex_t mutex;
pthread_t poller_threadID;

u8 own_privkey_buf[PRIVKEY_LEN];

u8 temp_handshake_memory_region_isLocked = 0;

struct bigint *M, *Q, *G, *Gm, *server_pubkey_bigint, *own_privkey, *own_pubkey;

/* Memory region holding short-term cryptographic artifacts for Login scheme. */
u8* temp_handshake_buf;

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

/* Linux Sockets API related globals. */
int port = SERVER_PORT
   ,own_socket_fd
   ,optval1 = 1
   ,optval2 = 2;

socklen_t server_addr_len = sizeof(struct sockaddr_in);

struct sockaddr_in server_address;


/* First thing done when we start the client software - initialize it. */
u32 self_init(){

    /* Allocate memory for the temporary login handshake memory region. */
    temp_handshake_buf = calloc(1, TEMP_BUF_SIZ);
 
    /* Initialize our own socket. */
    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(own_socket_fd == -1) {
        printf("[ERR] Client: Own TCP socket init failed. Terminating.\n");
        return 1;
    }

    setsockopt(
          own_socket_fd, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1)
    );  
      
    setsockopt(
          own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2)
    );
    
    explicit_bzero(&server_address, sizeof(struct sockaddr_in));
 
    /* Initialize the server address structure. */
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("212.104.116.132");
    servaddr.sin_port        = htons(PORT);
 
    /* Load our own private key. */
    FILE* privkey_dat = fopen("client_privkey.dat", "r"); 
    
    if(!privkey_dat){
        printf("[ERR] Client: couldn't open private key DAT file. Aborting.\n");
        return 1;
    }       
    
    if(fread(own_privkey_buf, 1, PRIVKEY_LEN, privkey_dat) != PRIVKEY_LEN){
        printf("[ERR] Client: couldn't get private key from file. Aborting.\n");
        fclose(privkey_dat);
        return 1;
    }

    fclose(privkey_dat);

    /* Initialize the BigInt that stores our private key. */
    bigint_create(&own_privkey, MAX_BIGINT_SIZ, 0);
    memcpy(own_privkey.bits, own_privkey_buf, PRIVKEY_LEN);     
    own_privkey.used_bits = get_used_bits(own_privkey_buf, PRIVKEY_LEN);                            
    own_privkey.free_bits = MAX_BIGINT_SIZ - own_privkey.used_bits;   

    /* Load in other BigInts needed for the cryptography to work. */
    
    /* Diffie-Hellman modulus M, 3071-bit prime number */                        
    M = get_BIGINT_from_DAT
        (3072, "../../saved_nums/M_raw_bytes.dat\0", 3071, MAX_BIGINT_SIZ);
    
    /* 320-bit prime exactly dividing M-1, making M cryptographycally strong. */
    Q = get_BIGINT_from_DAT
        (320,  "../../saved_nums/Q_raw_bytes.dat\0", 320,  MAX_BIGINT_SIZ);
    
    /* Diffie-Hellman generator G = G = 2^((M-1)/Q) */
    G = get_BIGINT_from_DAT
        (3072, "../../saved_nums/G_raw_bytes.dat\0", 3071, MAX_BIGINT_SIZ);

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_BIGINT_from_DAT( 3072
                             ,"../../saved_nums/PRACTICAL_Gmont_raw_bytes.dat\0"
                             ,3071
                             ,MAX_BIGINT_SIZ
    );
    
    server_pubkey_bigint = get_BIGINT_from_DAT
        (3072, "../../saved_nums/server_pubkey.dat\0", 3071, MAX_BIGINT_SIZ);
        
    own_pubkey = get_BIGINT_from_DAT
        (3072, "../../saved_nums/own_pubkey.dat\0", 3071, MAX_BIGINT_SIZ);
    
    /* Initialize the mutex that will be used to prevent the main thread and
     * the poller thread from writing/reading the same data in parallel.
     */
    if (pthread_mutex_init(&mutex, NULL) != 0) { 
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n"); 
        return 1; 
    } 
  
    return 0;
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

    bigint* a_s;
    bigint* A_s;
    
    u8 status = 0;
    
    const u64 msg_len = SMALL_FIELD_LEN + PUBKEY_LEN;
    u8* msg_buf = calloc(1, msg_len);

    /* Generate client's short-term public, private keys and ChaCha nonce N, and 
     * shared secret and thus bidirectional keys KAB, KBA and "unused" part Y:
     *
     *
     *       First section - reserved for server's short-term PubKey B_s
     *
     *       a_s = random in the range [1, Q)
     * 
     *       A_s = G^b_s mod M     <--- Montgomery Form of G.
     *   
     *       X_s = A_s^b_s mod M   <--- Montgomery Form of A_s.
     *
     *       KAB_s = X_s[0  .. 31 ]
     *       KBA_s = X_s[32 .. 63 ]
     *       Y_s   = X_s[64 .. 95 ] 
     *       N_s   = X_s[96 .. 107] <--- 12-byte Nonce for ChaCha20.    
     */

    gen_priv_key(PRIVKEY_LEN, (temp_handshake_buf + sizeof(bigint)));
    
    a_s = (bigint*)(temp_handshake_buf + sizeof(bigint));

    /* Interface generating a pub_key still needs priv_key in a file. Change. */
    save_BIGINT_to_DAT("temp_privkey_DAT\0", a_s);
  
    A_s = gen_pub_key(PRIVKEY_LEN, "temp_privkey_DAT\0", MAX_BIGINT_SIZ);
    
    /* Place the server short-term pub_key also in the locked memory region. */
    memcpy((temp_handshake_buf + (2 * sizeof(bigint))), A_s, sizeof(bigint));

    /* Establish an initial connection to the Rosetta TCP server. */
    printf("[OK]  Client: Now connecting to the Rosetta TCP server...\n");
    
    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) ){
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        printf("              Aborting Login...\n\n");
        status = 1;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Connected to the Rosetta TCP server!\n");
    }
    
    /* Construct and send the MSG buffer to the TCP server. */
    
    *((u64*)(msg_buf)) = (u64)PACKET_ID_00;
    
    memcpy(msg_buf + SMALL_FIELD_LEN, A_s->bits, PUBKEY_LEN);
    
    if(send(own_socket_fd, msg_buf, msg_len) == -1){
        printf("[ERR] Client: Couldn't send initial login transmission.\n");
        printf("[ERR]         Aborting Login...\n\n");
        status = 1;
        goto label_cleanup;
    }
    else{
        printf("[OK]  Client: Sent initial login transmission!\n");
    }
    
label_cleanup:

    system("rm temp_privkey_DAT");
    free(msg_buf);
    
    return status;
}

/* Server sent its short-term public key too, so the client can now compute a
   shared secret and transport its LONG-TERM public key in encrypted form.
   
    Server ----> Client

================================================================================
| PACKET_ID_00 | Server's one time PubKey | Signature of unused part of X: Y_s |
|==============|==========================|====================================|
|  SMALL_LEN   |       PUBKEY_LEN         |             SIGNATURE_LEN          |
--------------------------------------------------------------------------------

*/  
void process_msg_00(u8* msg_buf){



}










