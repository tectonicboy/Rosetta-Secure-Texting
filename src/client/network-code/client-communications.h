#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#define SERVER_PORT             54746
#define MAX_SOCK_QUEUE          1024
#define SERVER_IP_ADDR          "192.168.0.112"
#define MAX_RECV_RETRIES        100
#define RECV_RETRY_AFTER_MICROS 20000

const int port = SERVER_PORT;
const int optval1 = 1;
      int own_socket_fd = -1;

const socklen_t server_addr_len = sizeof(struct sockaddr_in);

struct sockaddr_in servaddr;

#define SOCK_PATH     "/usr/bin/rosetta.sock\0"
#define SOCK_PATH_LEN strlen("/usr/bin/rosetta.sock\0")

struct sockaddr_un unix_server_addr;

int sock_path_len = 0;


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

    if(fcntl(own_socket_fd, F_SETFL, O_NONBLOCK) == -1){
        printf("[ERR] Client: fcntl() O_NONBLOCK for socket fd failed.\n");
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
        goto label_cleanup;
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

    if(send(own_socket_fd, msg_buf, msg_len, 0) != (ssize_t)msg_len){
        ret = 1;
        perror("[ERR] Client: TCP send() failed! errno: ");
    }

    return ret;
}

u8 tcp_receive_payload(u8* reply_buf, u64* reply_len){

    uint8_t  ret = 0;
    ssize_t  status = 0;    
    uint64_t retry_counter = 0;

    while(    ((status = recv(own_socket_fd, reply_buf, 8192, 0)) == -1)
           && errno == EWOULDBLOCK
           && retry_counter < MAX_RECV_RETRIES
         )
    {
        usleep(RECV_RETRY_AFTER_MICROS);
        ++retry_counter;
    }

    if(__builtin_expect(retry_counter == MAX_RECV_RETRIES, 0)){
        printf("[ERR] Client: TCP recv reached max retries. No connection.\n");
        ret = 2;
        *reply_len = 0;
    }

    if(__builtin_expect(status == -1 && errno != EWOULDBLOCK, 0)){
        printf("\n[ERR] Client: TCP recv() failed! errno: ");
        ret = 1;
        *reply_len = 0;
    }
    else{
        *reply_len = status;
    }
    

    return ret;
}

void tcp_end_communication(void)
{
    close(own_socket_fd);       
    return;
}

uint8_t ipc_init_communication(){

    int len = 0;

    uint8_t ret    = 0;
    int     status = 0;

    /**************************************************************************/

    own_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(own_socket_fd < 0){
        perror("[ERR] Client: AF_UNIX socket() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Client: AF_UNIX socket() call is OK.\n");

    if(fcntl(own_socket_fd, F_SETFL, O_NONBLOCK) == -1){
        printf("[ERR] Client: fcntl() O_NONBLOCK for socket fd failed.\n");
        perror("errno:");
        goto label_cleanup;
    }

    /**************************************************************************/

    memset(&unix_server_addr, 0x00, sizeof(struct sockaddr_un));
    unix_server_addr.sun_family = AF_UNIX;
    sock_path_len = SOCK_PATH_LEN;
    strncpy(unix_server_addr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);
    len = sock_path_len + 1 + sizeof(unix_server_addr.sun_family);

    status = connect(own_socket_fd, (struct sockaddr*)&unix_server_addr, len);

    if(status == -1){
        perror("[ERR] Client: AF_UNIX connect() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Client: AF_UNIX connect() call is OK.\n");

    /**************************************************************************/

    goto label_init_successful;

label_cleanup:

    if(own_socket_fd != -1)
        close(own_socket_fd);

label_init_successful:

    return ret;
}

uint8_t ipc_transmit_payload(uint8_t* buf, size_t buf_len){

    uint8_t ret = 0;

    if(send(own_socket_fd, buf, buf_len, 0) != (ssize_t)buf_len){
        perror("[ERR] Client: AF_UNIX test send() failed.\n");
        ret = 1;
    }

    return ret;
}

uint8_t ipc_receive_payload(uint8_t* buf, uint64_t* recv_len){

    uint8_t  ret    = 0;
    ssize_t  status = 0;
    uint64_t retry_counter = 0;

    while(    ((status = recv(own_socket_fd, buf, 8192, 0)) == -1)
           && errno == EWOULDBLOCK
           && retry_counter < MAX_RECV_RETRIES
         )
    {
        usleep(RECV_RETRY_AFTER_MICROS);
        ++retry_counter;
    }

    if(__builtin_expect(retry_counter == MAX_RECV_RETRIES, 0)){
        printf("[ERR] Client: TCP recv reached max retries. No connection.\n");
        ret = 2;
        *recv_len = 0;
    }

    if(__builtin_expect(status == -1 && errno != EWOULDBLOCK, 0)){
        printf("\n[ERR] Client: TCP recv() failed! errno: ");
        ret = 1;
        *recv_len = 0;
    }
    else{
        *recv_len = status;
    }

    return ret;
}

void ipc_end_communication(void)                                                 
{                                                                                
    close(own_socket_fd);                                                        
    return;                                                                      
}  

