#include "communication-constructs.h"

uint8_t tcp_init_communication(void){

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

uint8_t tcp_onboard_new_client(uint32_t socket_ix){

    uint8_t ret = 0;

    client_socket_fd[socket_ix] =                                  
            accept( listening_socket
                   ,(struct sockaddr*)(&(client_addresses[socket_ix]))
                   ,&(clientLens[socket_ix])
                  );
                                                                   
    if(client_socket_fd[curr_free_socket_ix] == -1){                         
        perror("[ERR] Server: TCP accept() failed, errno: ");
        ret = 1;
    }                                                                        
    else
        printf("[OK] Server: TCP accept() is OK. New client allowed in!\n");

    return ret;
}

uint8_t tcp_transmit_payload(uint32_t socket_ix, uint8_t* buf, size_t send_len){

    uint8_t ret = 0;

    if(send(client_socket_fd[socket_ix], buf, sendlen, 0) == -1){
        perror("[ERR] Server: TCP send() failed! errno: ");
        ret = 1;
    }

    return ret;
}

uint8_t tcp_receive_payload(uint32_t socket_ix, uint8_t* buf, size_t max_len){

    uint8_t ret = 0;
    ssize_t bytes_read;

    bytes_read = recv(client_socket_fd[ix], client_msg_buf, max_len, 0);

    if(bytes_read == -1){
        perror("[ERR] Server: TCP receiving failed! errno: ");
        ret = 1;
    }

    return ret;
}
