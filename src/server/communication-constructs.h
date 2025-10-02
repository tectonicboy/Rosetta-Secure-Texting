#include <sys/socket.h>                                                          
#include <sys/types.h>                                                           
#include <netinet/in.h>                                                          
#include <arpa/inet.h>                                                           
#include <sys/un.h>  

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
                                                                                 
#define SERVER_PORT    54746                                                     
#define MAX_SOCK_QUEUE 1024                                                      
                                                                                 
/* Linux Sockets API related globals. */                                         
int port = SERVER_PORT;                                                          
int listening_socket;                                                            
int optval1 = 1;                                                                 
int optval2 = 2;                                                                 
                                                                                 
int client_socket_fd[MAX_CLIENTS];                                               
struct sockaddr_in client_addresses[MAX_CLIENTS];                                
socklen_t clientLens[MAX_CLIENTS];                                               
struct sockaddr_in tcp_servaddr;
struct sockaddr_un ipc_servaddr;

#define BUF_SIZ       100                                                        
#define SOCK_PATH     "/usr/bin/rosetta.sock\0"                                  
#define SOCK_PATH_LEN strlen("/usr/bin/rosetta.sock\0") 
