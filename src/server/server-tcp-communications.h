#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
struct sockaddr_in servaddr;

uint8_t init_tcp_listening(void){

    uint8_t status = 0;

    for(socklen_t i = 0; i < MAX_CLIENTS; ++i){
        clientLens[i] = sizeof(struct sockaddr_in);
    }

    /* Initialize the server address structure. */
    servaddr.sin_family      = AF_INET;
    servaddr.sin_port        = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    /* Obtain the file descriptor for the listen()ing socket. */                 
    if( (listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("[ERR] Server: Could not open server socket. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1)
    );

    setsockopt(
          listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2)
    );

    if( (bind(listening_socket, (struct sockaddr*)&servaddr, sizeof(servaddr)))
        == -1
       &&
        (errno != 13)
      )
    {
        printf("[ERR] Server: bind() failed. Errno != 13. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    /* Put the listen()ing socket in a state of listening for connections. */
    if( (listen(listening_socket, MAX_SOCK_QUEUE)) == -1){
        printf("[ERR] Server: couldn't begin listen()ing. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

    goto label_finished;

/******************************************************************************/

label_cleanup:

    if(listening_socket){
        close(listening_socket);
    }

label_finished:

    return status;

}
