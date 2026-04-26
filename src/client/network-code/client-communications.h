#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* recv() shall timeout after 3 seconds thanks to SO_RCVTIMEO socket option. */
#define RECV_TIMEOUT_AFTER_SEC  3
#define SERVER_PORT             54746
#define SERVER_IP_ADDR          "13.63.197.0"
#define MAX_RECV_RETRIES        400
#define RECV_RETRY_AFTER_MICROS 5000
#define POLL_INTERVAL_MICROS    100000 /* Poll the server every 0.1 seconds */

/* recv() shall timeout after 3 seconds thanks to SO_RCVTIMEO socket option. */
#define RECV_TIMEOUT_AFTER_SEC  3

const int port = SERVER_PORT;
const int optval1 = 1;
      int own_socket_fd = -1;
      int sock_path_len;

/* Local interprocess communications for Rosetta Test Framework. */
#define SOCK_PATH       "/usr/bin/rosetta.sock\0"
#define SOCK_PATH_LEN   strlen("/usr/bin/rosetta.sock\0")

const socklen_t    server_addr_len = sizeof(struct sockaddr_in);
struct sockaddr_in servaddr;
struct sockaddr_un unix_server_addr;

uint8_t tcp_init_communication()
{
    uint8_t ret = 0;

    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDR);
    servaddr.sin_port        = htons(port);
    own_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(own_socket_fd == -1) {
        perror("[ERR] Client: TCP socket() call failed. ERRNO: ");
        goto label_error;
    }
    printf("[OK]  Client: TCP socket file descriptor obtained!\n");
    if(setsockopt(own_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval1,
                  sizeof(optval1))
       == -1)
    {
        perror("[ERR] Client: TCP setsockopt() for REUSEADDR failed: ");
        goto label_error;
    }
    printf("[OK]  Client: TCP socket option for REUSEADDR has been set.\n");
    struct timeval tv;
    tv.tv_sec  = RECV_TIMEOUT_AFTER_SEC;
    tv.tv_usec = 0;
    if(setsockopt(own_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
       == -1)
    {
        perror("[ERR] Client: TCP setsockopt() for RCVTIMEO failed: ");
        goto label_error;
    }
    printf("[OK]  Client: TCP socket option for RCVTIMEO has been set.\n");
    /* Connect to the Rosetta server. */
    if(connect(own_socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        == -1)
    {
        perror("[ERR] Client: TCP connecting to Rosetta server failed: ");
        goto label_error;
    }
    printf("[OK]  Client: TCP connected to Rosetta server!\n");
    goto label_finished;

label_error:
		ret = 1;
    if(own_socket_fd != -1){
        close(own_socket_fd);
    }

label_finished:
    return ret;
}

u8 tcp_transmit_payload(u8* msg_buf, u64 msg_len)
{
    uint8_t ret = 0;
    if( __builtin_expect
			 (send(own_socket_fd, msg_buf, msg_len, 0) != (ssize_t)msg_len, false))
		{
        ret = 1;
        perror("[ERR] Client: TCP send() call failed: ");
    }
    return ret;
}

u8 tcp_receive_payload(u8* reply_buf, u64* reply_len)
{
    uint8_t  ret = 0;
    ssize_t  status = 0;

    status = recv(own_socket_fd, reply_buf, MAX_MSG_LEN, 0);
    if( __builtin_expect (status == 0, false) ){
        printf("[OK]  Client: TCP Server gracefully ended communication.\n");
        ret = 1;
        *reply_len = 0;
    }
    else if( __builtin_expect (status == -1, false) ){
        if(errno != EAGAIN
           #if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
           && errno != EWOULDBLOCK
           #endif
          )
        {
            perror("[ERR] Client: TCP recv() from server failed unexpectedly:");
            ret = 1;
        }
        else{
            printf("[ERR] Client: TCP recv() from server TIMED OUT!\n");
            ret = 2;
        }
        *reply_len = 0;
    }
    else{
        *reply_len = status;
    }

    return ret;
}

void tcp_end_communication(void)
{
    if(close(own_socket_fd) == -1){
        perror("[ERR] Client: TCP close() to end communication failed: ");
		}
		else{
        printf("[OK]  Client: TCP closed communication with server.\n ");
		}
    return;
}

uint8_t ipc_init_communication()
{
    int     len    = 0;
    uint8_t ret    = 0;
    int     status = 0;

    own_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(own_socket_fd == -1){
        perror("[ERR] Client: AF_UNIX socket() call failed: ");
        goto label_error;
    }
    printf("[OK]  Client: AF_UNIX socket file descriptor obtained!\n");
    struct timeval tv;
    tv.tv_sec  = RECV_TIMEOUT_AFTER_SEC;
    tv.tv_usec = 0;
    if(setsockopt(own_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
       == -1)
    {
        perror("[ERR] Client: AF_UNIX setsockopt() for RCVTIMEO failed: ");
        goto label_error;
    }
    printf("[OK]  Client: AF_UNIX socket option RCVTIMEO has been set.\n");
    memset(&unix_server_addr, 0x00, sizeof(struct sockaddr_un));
    unix_server_addr.sun_family = AF_UNIX;
    sock_path_len = SOCK_PATH_LEN;
    strncpy(unix_server_addr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);
    len = sock_path_len + 1 + sizeof(unix_server_addr.sun_family);
    status = connect(own_socket_fd, (struct sockaddr*)&unix_server_addr, len);
    if(status == -1){
        perror("[ERR] Client: AF_UNIX connect() call failed: ");
        goto label_error;
    }
    printf("[OK]  Client: AF_UNIX connected to Rosetta server now!\n");
    goto label_init_successful;

label_error:
		ret = 1;
    if(own_socket_fd != -1){
        close(own_socket_fd);
    }

label_init_successful:
    return ret;
}

uint8_t ipc_transmit_payload(uint8_t* buf, size_t buf_len)
{
    uint8_t ret = 0;

    if( __builtin_expect
			  (send(own_socket_fd, buf, buf_len, 0) != (ssize_t)buf_len, false)){
        perror("[ERR] Client: AF_UNIX send() call failed: ");
        ret = 1;
    }
    return ret;
}

uint8_t ipc_receive_payload(uint8_t* buf, uint64_t* recv_len)
{
    uint8_t  ret    = 0;
    ssize_t  status = 0;

    status = recv(own_socket_fd, buf, MAX_MSG_LEN, 0);
    if( __builtin_expect (status == 0, false) ){
        printf("[OK]  Client: AF_UNIX server gracefully closed connection.\n");
        ret = 1;
        *recv_len = 0;
    }
    else if( __builtin_expect (status == -1, false) ){
        if(errno != EAGAIN
           #if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
           && errno != EWOULDBLOCK
           #endif
          )
        {
            perror("[ERR] Client: AF_UNIX recv() from server failed unexpectedly:");
            ret = 1;
        }
        else{
            printf("[ERR] Client: AF_UNIX recv() from server TIMED OUT!\n");
            ret = 2;
        }
        *recv_len = 0;
    }
    else{
        *recv_len = status;
    }
    return ret;
}

void ipc_end_communication(void)
{
    if(close(own_socket_fd) == -1){
        perror("[ERR] Client: AF_UNIX close() call on the socket failed: ");
		}
		else{
        printf("[OK]  Client: AF_UNIX closed socket successfully.\n");
		}
    return;
}
