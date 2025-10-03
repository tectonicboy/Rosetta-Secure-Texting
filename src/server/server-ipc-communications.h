#include "communication-constructs.h"

uint8_t init_server_ipc_comms()
{
    uint8_t ret = 0;

    char buf[BUF_SIZ];

    ssize_t num_read;

    /**************************************************************************/

    listening_socket = socket(AF_UNIX, SOCK_STREAM, 0);
   
    if(listening_socket == -1){
        perror("[ERR] Server: AF_UNIX socket() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    unlink(SOCK_PATH);

    /**************************************************************************/

    memset(&ipc_servaddr, 0, sizeof(struct sockaddr_un));
    ipc_servaddr.sun_family = AF_UNIX;
    strncpy(ipc_addr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);
    
    if (bind( listening_socket
             ,(struct sockaddr*)&ipc_servaddr
             ,sizeof(struct sockaddr_un)
            ) == -1
       ) 
    {
        perror("[ERR] Communications Layer: AF_UNIX bind() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    if(listen(listening_socket, 50) == -1){
        perror("[ERR] Communications Layer: AF_UNIX listen() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    goto label_init_succeeded;

    /**************************************************************************/

label_cleanup:

    if(listening_socket != -1)
        close(listening_socket);

    unlink(SOCK_PATH);

label_init_succeeded:

    return ret;
}

uint8_t ipc_onboard_new_client(uint32_t socket_ix){

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

uint8_t ipc_transmit_payload(uint32_t socket_ix, uint8_t* buf, size_t max_len){

    uint8_t ret = 0;

    if(send(client_socket_fd[socket_ix], buf, sendlen, 0) == -1){
        perror("[ERR] Server: AF_UNIX send() failed! errno: ");
        ret = 1;
    }

    return ret;
}

uint8_t ipc_receive_payload(uint32_t socket_ix, uint8_t* buf, size_t max_len){

    uint8_t ret = 0;

    ssize_t num_read;

    if((num_read = recv(client_socket_fd[socket_ix], buf, max_len, 0)) == -1){
        perror("[ERR] Server: AF_UNIX recv() call failed! errno: ");
        ret = 1;                                                                 
    }                       

    return ret;
}






