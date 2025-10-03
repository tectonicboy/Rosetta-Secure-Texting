#include <netinet/in.h>
#include <sys/un.h>

#define SOCK_PATH     "/usr/bin/rosetta.sock\0"
#define SOCK_PATH_LEN strlen("/usr/bin/rosetta.sock\0")

struct sockaddr_un unix_server_addr;

int own_socket_fd = -1;
int sock_path_len = 0;

uint8_t ipc_init_communication(){

    int len = 0;

    uint8_t ret = 0;
 
    /**************************************************************************/

    own_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(own_socket_fd < 0){
        perror("[ERR] Client: AF_UNIX socket() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Client: AF_UNIX socket() call is OK.\n");

    /**************************************************************************/

    memset(&unix_server_addr, 0x00, sizeof(struct sockaddr_un));
    unix_server_addr.sun_family = AF_UNIX;
    sock_path_len = SOCK_PATH_LEN;
    strncpy(unix_server_addr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);
    len = sock_path_len + 1 + sizeof(unix_server_addr.sun_family);

    ret = connect(own_socket_fd, (struct sockaddr*)&unix_server_addr, len);

    if(ret == -1){
        perror("[ERR] Client: AF_UNIX connect() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Client: AF_UNIX connect() call is OK.\n");
    
    /**************************************************************************/

    goto label_init_successful;

label_cleanup:

    if(unix_socket_fd != -1)
        close(unix_socket_fd);

label_init_successful:

    return ret;
}

uint8_t ipc_transmit_payload(uint8_t* buf, size_t buf_len){

    uint8_t ret = 0;  

    if(send(own_socket_fd, buf, buf_len, 0) != buf_len){
        perror("[ERR] Client: AF_UNIX test send() failed.\n");    
        ret = 1;                                                                 
    }

    return ret;
}

uint8_t ipc_receive_payload(uint8_t* buf, uint64_t* recv_len){

    uint8_t ret = 0;

    (int64_t)(*recv_len) = (int64_t)recv(own_socket_fd, buf, 8192, 0);

    if( ((int64_t)(*recv_len)) == -1){
        printf("\n[ERR] Client: AF_UNIX recv() failed! errno: ");
        ret = 1;
    }

    return ret;
}

