#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <errno.h>

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

uint8_t tcp_init_communication(void){

    uint8_t status = 0;

    for(socklen_t i = 0; i < MAX_CLIENTS; ++i){
        clientLens[i] = sizeof(struct sockaddr_in);
    }

    /* Initialize the server address structure. */
    tcp_servaddr.sin_family      = AF_INET;

    tcp_servaddr.sin_port        = htons(port);
    tcp_servaddr.sin_addr.s_addr = INADDR_ANY;

    /**************************************************************************/

    if( (listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("[ERR] Server: Could not open server socket. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1)
    );

    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2)
    );

    /**************************************************************************/

    if( (bind
      (listening_socket, (struct sockaddr*)&tcp_servaddr, sizeof(tcp_servaddr))
        )
        == -1
       &&
        (errno != 13)
      )
    {
        printf("[ERR] Server: bind() failed. Errno != 13. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    if( (listen(listening_socket, MAX_SOCK_QUEUE)) == -1){
        printf("[ERR] Server: couldn't begin listen()ing. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    goto label_finished;

    /**************************************************************************/

label_cleanup:

    if(listening_socket){
        close(listening_socket);
    }

label_finished:

    return status;

}

uint8_t tcp_onboard_new_client(uint64_t socket_ix){

    uint8_t ret = 0;

    client_socket_fd[socket_ix] =
            accept( listening_socket
                   ,(struct sockaddr*)(&(client_addresses[socket_ix]))
                   ,&(clientLens[socket_ix])
                  );

    if(client_socket_fd[socket_ix] == -1){
        perror("[ERR] Server: TCP accept() failed, errno: ");
        ret = 1;
    }
    else
        printf("[OK] Server: TCP accept() is OK. New client allowed in!\n");

    return ret;
}

uint8_t tcp_transmit_payload(uint64_t socket_ix, uint8_t* buf, size_t send_len){

    uint8_t ret = 0;

    if(send(client_socket_fd[socket_ix], buf, send_len, 0) == -1){
        perror("[ERR] Server: TCP send() failed! errno: ");
        ret = 1;
    }

    return ret;
}

ssize_t tcp_receive_payload(uint64_t socket_ix, uint8_t* buf, size_t max_len){

    ssize_t bytes_read;

    bytes_read = recv(client_socket_fd[socket_ix], buf, max_len, 0);

    if(bytes_read == -1){
        if(errno == EINTR){
            printf("[OK] Server: recv in sock[%lu] got a SIGNAL!\n", socket_ix);
            return -1;
        }
        perror("[ERR] Server: TCP receiving failed! errno: ");
        printf("            : socket_ix = [%lu]\n", socket_ix);
        return -1;
    }

    return bytes_read;
}

uint8_t ipc_init_communication()
{
    uint8_t ret = 0;

    /**************************************************************************/

    listening_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    if(listening_socket == -1){
        perror("[ERR] Server: AF_UNIX socket() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Server: AF_UNIX socket() call is OK.\n");
  
    unlink(SOCK_PATH);

    /**************************************************************************/

    memset(&ipc_servaddr, 0, sizeof(struct sockaddr_un));
    ipc_servaddr.sun_family = AF_UNIX;
    strncpy(ipc_servaddr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);

    if (bind( listening_socket
             ,(struct sockaddr*)&ipc_servaddr
             ,sizeof(struct sockaddr_un)
            ) == -1
       )
    {
        perror("[ERR] Server: AF_UNIX bind() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Server: AF_UNIX bind()   call is OK.\n");

    /**************************************************************************/

    if(listen(listening_socket, 50) == -1){
        perror("[ERR] Server: AF_UNIX listen() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Server: AF_UNIX listen() call is OK.\n");

    /**************************************************************************/

    goto label_init_succeeded;

    /**************************************************************************/

label_cleanup:

    if(listening_socket != -1)
        close(listening_socket);

    unlink(SOCK_PATH);

label_init_succeeded:

    printf("[OK]  Server: Local interprocess communication init finished!!\n");

    return ret;
}

uint8_t ipc_onboard_new_client(uint64_t socket_ix){

    uint8_t ret = 0;

    client_socket_fd[socket_ix] = accept(listening_socket, NULL, NULL);

    if (client_socket_fd[socket_ix] == -1) {                                      
        perror("[ERR] Server: AF_UNIX accept() call failed!\n");
        ret = 1;
    }
    else
        printf("[OK]  Server: AF_UNIX accept() is OK. Accepted new client!\n");

    return ret;
}

uint8_t ipc_transmit_payload(uint64_t socket_ix, uint8_t* buf, size_t send_len){

    uint8_t ret = 0;

    if(send(client_socket_fd[socket_ix], buf, send_len, 0) == -1){
        perror("[ERR] Server: AF_UNIX send() failed! errno: ");
        ret = 1;
    }

    return ret;
}

ssize_t ipc_receive_payload(uint64_t socket_ix, uint8_t* buf, size_t max_len){

    ssize_t num_read;

    if((num_read = recv(client_socket_fd[socket_ix], buf, max_len, 0)) == -1){
        if(erno == EINTR){
            printf("[OK] Server: recv in sock[%lu] got a SIGNAL!\n", socket_ix);
            return -1;
        }
        perror("[ERR] Server: AF_UNIX receiving failed! errno: ");                   
        printf("            : socket_ix = [%lu]\n", socket_ix);
        return -1;
    }

    return num_read;
}
