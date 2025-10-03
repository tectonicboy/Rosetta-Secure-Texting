#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT    54746
#define MAX_SOCK_QUEUE 1024
#define SERVER_IP_ADDR "192.168.0.112"

const int port = SERVER_PORT;
const int optval1 = 1;
      int own_socket_fd = -1;

const socklen_t server_addr_len = sizeof(struct sockaddr_in);

struct sockaddr_in servaddr;

uint8_t tcp_init_communication(){

    uint8_t ret = 0;

    memset(&servaddr, 0, sizeof(struct sockaddr_in));

    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDR);
    servaddr.sin_port        = htons(port);

    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(own_socket_fd == -1) {
        printf("[ERR] Client: socket() failed. Terminating.\n");
        perror("errno:");
        goto label_cleanup;
    }

    if(
        setsockopt(
           own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval1, sizeof(optval1)
        )
        != 0
    )
    {
        printf("[ERR] Client: set socket option failed.\n\n");
        label_cleanup;
    }

    printf("[OK]  Client: Socket file descriptor obtained!\n");

    /* Connect to the Rosetta server. */

    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        == -1
      )
    {
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        perror("connect() failed, errno: ");
        goto label_cleanup;
    }

    printf("[OK]  Client: Successfully connected to the Rosetta server!\n\n");
    goto label_finished;

label_cleanup:
    
    ret = 1;

    if(own_socket_fd != -1)
        close(own_socket_fd);
    
label_finished:

    return ret;
}

u8 tcp_transmit_payload(u8* msg_buf, u64 msg_len){

    uint8_t ret = 0;
 
    if(send(own_socket_fd, msg_buf, msg_len, 0) != msg_len){
        ret = 1;
        perror("[ERR] Client: TCP send() failed! errno: ");
    }

    return ret;
}

u8 tcp_receive_payload(u8* reply_buf, u64* reply_len){
 
    uint8_t ret = 0;

    (int64_t)(*reply_len) = (int64_t)recv(own_socket_fd, reply_buf, 8192, 0);
     
    if( ((int64_t)(*reply_len)) == -1){
        printf("\n[ERR] Client: TCP recv() failed! errno: ");
        ret = 1;
    }

    return ret;
}
