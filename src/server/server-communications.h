#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

/* recv() shall timeout after 3 seconds thanks to SO_RCVTIMEO socket option. */
#define RECV_TIMEOUT_AFTER_SEC    3
#define SERVER_PORT               54746
#define CONNECTIONS_BACKLOG_LIMIT 50
#define RETRY_RECV_DELAY_MICROS   5000
#define RETRY_RECV_MAX_ATTEMPTS   400

/* Linux Sockets API related. */
int port = SERVER_PORT;
int listening_socket;
int optval1 = 1;
int optval2 = 2;
int client_socket_fd[MAX_CLIENTS];
struct sockaddr_in client_addresses[MAX_CLIENTS];
socklen_t clientLens[MAX_CLIENTS];
struct sockaddr_in tcp_servaddr;
struct sockaddr_un ipc_servaddr;

/* For local interprocess communications for the Rosetta Test Framework. */
#define AF_UNIX_SOCK_PATH     "/usr/bin/rosetta.sock\0"
#define AF_UNIX_SOCK_PATH_LEN strlen("/usr/bin/rosetta.sock\0")

uint8_t tcp_init_communication(void)
{
    uint8_t status = 0;

    for(socklen_t i = 0; i < MAX_CLIENTS; ++i){
        clientLens[i] = sizeof(struct sockaddr_in);
    }
    /* Initialize the server address structure. */
    tcp_servaddr.sin_family      = AF_INET;
    tcp_servaddr.sin_port        = htons(port);
    tcp_servaddr.sin_addr.s_addr = INADDR_ANY;

    if((listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("[ERR] Server: TCP socket() call failed: ");
        goto label_error;
    }
		printf("[OK]  Server: TCP socket file descriptor obtained.\n");
    if(setsockopt(listening_socket, SOL_SOCKET, SO_REUSEPORT, &optval1,
                  sizeof(optval1))
			 == -1)
		{
        perror("[ERR] Server: TCP setsockopt() for REUSEPORT failed: ");
				goto label_error;
		}
		printf("[OK]  Server: TCP socket option for REUSEPORT has been set.\n");
    if(setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval2,
                  sizeof(optval2))
			 == -1)
    {
        perror("[ERR] TCP socket option for REUSEADDR failed: ");
				goto label_error;
	  }
    printf("[OK]  Server: TCP socket option for REUSEADDR has been set.\n");
    if( bind(listening_socket, (struct sockaddr*)&tcp_servaddr,
             sizeof(tcp_servaddr))
        == -1
        &&
        (errno != 13))
    {
        printf("[ERR] Server: TCP bind() failed. Errno != 13. Aborting.\n");
				perror("errno: ");
        goto label_error;
    }
		printf("[OK]  Server: TCP bind() call successful.\n");
    if( (listen(listening_socket, CONNECTIONS_BACKLOG_LIMIT)) == -1){
        perror("[ERR] Server: TCP listen() call failed: ");
        goto label_error;
    }
    printf("[OK]  Server: TCP listen() call successful.\n");
    goto label_finished;

label_error:
    if(listening_socket){
        close(listening_socket);
    }
		status = 1;

label_finished:
    return status;
}

uint8_t tcp_onboard_new_client(uint64_t socket_ix)
{
    client_socket_fd[socket_ix] =
      accept( listening_socket,
              (struct sockaddr*)(&(client_addresses[socket_ix])),
              &(clientLens[socket_ix]));

    if(client_socket_fd[socket_ix] == -1){
        printf("[ERR] Server: TCP accept() for client[%lu] failed\n",socket_ix);
				perror("errno: ");
        return 1;
    }
    else{
        printf("[OK]  Server: TCP client[%lu] has been accepted!\n", socket_ix);
    }

    struct timeval tv;
    tv.tv_sec  = RECV_TIMEOUT_AFTER_SEC;
    tv.tv_usec = 0;

    if(setsockopt(client_socket_fd[socket_ix], SOL_SOCKET, SO_RCVTIMEO,
                  &tv, sizeof(tv))
       == -1)
    {
        printf("[ERR] Server: TCP setsockopt RCVTIMEO for client[%lu] failed\n",
							 socket_ix);
				perror("errno: ");
        close(client_socket_fd[socket_ix]);
				return 1;
    }
    printf("[OK]  Server: TCP socket option RCVTIMEO\n"
					 "              for client[%lu] has been set.\n", socket_ix);

    return 0;
}

uint8_t tcp_transmit_payload(uint64_t socket_ix, uint8_t* buf, size_t send_len)
{
    if( __builtin_expect
          (send(client_socket_fd[socket_ix], buf, send_len, 0) == -1, false))
    {
        printf("[ERR] Server: TCP send() for client[%lu] failed.\n", socket_ix);
				perror("errno: ");
        return 1;
    }
    else{
        return 0;
    }
}

ssize_t tcp_receive_payload(uint64_t socket_ix, uint8_t* buf, size_t max_len)
{
    ssize_t bytes_read = recv(client_socket_fd[socket_ix], buf, max_len, 0);

    /* Handle terminated communication - both graceful and unexpected. */
    if( __builtin_expect (bytes_read < 0, false) ){
        if(errno != EAGAIN
           #if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
           && errno != EWOULDBLOCK
           #endif
          )
        {
            printf("[ERR] Server: TCP client[%lu] recv fail\n", socket_ix);
            perror("errno: ");
        }
        else{
            printf("[ERR] Server: TCP client[%lu] recv timeout\n", socket_ix);
        }
    }
    if( __builtin_expect (bytes_read == 0, false) ){
        printf("[OK]  Server: AF_UNIX notified by client[%lu]'s OS:\n"
               "              gracefully ended communication.\n", socket_ix);
    }

    return bytes_read;
}

uint8_t ipc_init_communication()
{
    uint8_t ret = 0;
    listening_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(listening_socket == -1){
        perror("[ERR] Server: AF_UNIX socket() call failed: \n");
        goto label_error;
    }
    printf("[OK]  Server: AF_UNIX socket file descriptor obtained.\n");
    unlink(AF_UNIX_SOCK_PATH);
    memset(&ipc_servaddr, 0, sizeof(struct sockaddr_un));
    ipc_servaddr.sun_family = AF_UNIX;
    strncpy(ipc_servaddr.sun_path, AF_UNIX_SOCK_PATH, AF_UNIX_SOCK_PATH_LEN +1);
    if (bind(listening_socket, (struct sockaddr*)&ipc_servaddr,
             sizeof(struct sockaddr_un))
				== -1)
    {
        perror("[ERR] Server: AF_UNIX bind() call failed: ");
        goto label_error;
    }
    printf("[OK]  Server: AF_UNIX bind() call was successful.\n");

    if(listen(listening_socket, CONNECTIONS_BACKLOG_LIMIT) == -1){
        perror("[ERR] Server: AF_UNIX listen() call failed: ");
        goto label_error;
    }
    printf("[OK]  Server: AF_UNIX listen() call successful.\n");
		printf("[OK]  Server: Local interprocess communication INIT finished.\n");
    goto label_init_succeeded;

label_error:
    if(listening_socket != -1){
        close(listening_socket);
    }
    unlink(AF_UNIX_SOCK_PATH);
		ret = 1;

label_init_succeeded:

    return ret;
}

uint8_t ipc_onboard_new_client(uint64_t socket_ix)
{
    client_socket_fd[socket_ix] = accept(listening_socket, NULL, NULL);
    if(client_socket_fd[socket_ix] == -1){
        printf("[ERR] Server: AF_UNIX accept call for client[%lu] failed.\n",
							 socket_ix);
				perror("errno: ");
        return 1;
    }
    else{
        printf("[OK]  Server: AF_UNIX accepted client[%lu]!\n", socket_ix);
    }

    struct timeval tv;
    tv.tv_sec  = RECV_TIMEOUT_AFTER_SEC;
    tv.tv_usec = 0;

    if(setsockopt(client_socket_fd[socket_ix], SOL_SOCKET, SO_RCVTIMEO,
                  &tv, sizeof(tv))
       == -1)
    {
        printf("[ERR] Server: AF_UNIX setsockopt RCVTIMEO, client %lu fail.\n",
							 socket_ix);
				perror("errno: ");
        close(client_socket_fd[socket_ix]);
				return 1;
    }
    printf("[OK]  Server: AF_UNIX socket option for RCVTIMEO\n"
					 "              for client[%lu] has been set.\n", socket_ix);
    return 0;
}

uint8_t ipc_transmit_payload(uint64_t socket_ix, uint8_t* buf, size_t send_len)
{
    if( __builtin_expect
         (send(client_socket_fd[socket_ix], buf, send_len, 0) == -1, false))
    {
        printf("[ERR] Server: AF_UNIX send() failed, client[%lu]\n", socket_ix);
        return 1;
    }
    return 0;
}

ssize_t ipc_receive_payload(uint64_t socket_ix, uint8_t* buf, size_t max_len)
{
    ssize_t num_read = recv(client_socket_fd[socket_ix], buf, max_len, 0);

    /* Handle terminated communication - both graceful and unexpected cases. */
    if( __builtin_expect (num_read < 0, false) ){
        if(errno != EAGAIN
           #if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
           && errno != EWOULDBLOCK
           #endif
          )
        {
            printf("[ERR] Server: AF_UNIX client[%lu] poll recv failed.\n",
									 socket_ix);
            perror("errno: ");
        }
        else{
            printf("[ERR] Server: AF_UNIX client[%lu] poll recv timeout.\n",
									 socket_ix);
        }
    }
    else if( __builtin_expect (num_read == 0, false) ){
        printf("[OK]  Server: AF_UNIX notified by client[%lu]'s OS:\n"
               "              gracefully ended communication.\n", socket_ix);
    }
    return num_read;
}
