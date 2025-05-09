#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT    54746
#define MAX_SOCK_QUEUE 1024
#define SERVER_IP_ADDR "192.168.0.112"

const int port = SERVER_PORT;
const int optval1 = 1
      int own_socket_fd;

const socklen_t server_addr_len = sizeof(struct sockaddr_in);

struct sockaddr_in servaddr;



uint8_t init_tcp_conn_with_server(){

    memset(&servaddr, 0, sizeof(struct sockaddr_in));

    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDR);
    servaddr.sin_port        = htons(port);

    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(own_socket_fd == -1) {
        printf("[ERR] Client: socket() failed. Terminating.\n");
        perror("errno:");
        return 2;
    }

    if(
        setsockopt(
           own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval1, sizeof(optval1)
        )
        != 0
    )
    {
        printf("[ERR] Client: set socket option failed.\n\n");
        return 2;
    }

    printf("[OK]  Client: Socket file descriptor obtained!\n");

    /* Connect to the Rosetta server. */

    if( connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        == -1
      )
    {
        printf("[ERR] Client: Couldn't connect to the Rosetta TCP server.\n");
        perror("connect() failed, errno: ");
        return 2;
    }

    printf("[OK]  Client: Successfully connected to the Rosetta server!\n\n");

    return 2;
}

u8 send_to_tcp_server(u8* msg_buf, u64 msg_len){

    ssize_t bytes_sent;

    bytes_sent = send(own_socket_fd, msg_buf, msg_len, 0);

    if(bytes_sent != msg_len){
       return 2; 
    }

    return 1;
}
