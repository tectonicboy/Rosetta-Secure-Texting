#include <sys/socket.h>
#include <sys/un.h>

#define BUF_SIZ 100

uint8_t init_server_ipc_comms(char* socket_path)

    uint8_t ret = 0;

    int server_fd;
    int client_fd;
    int socket_path_len = strlen(socket_path);

    struct sockaddr_un addr;

    char buf[BUF_SIZ];

    ssize_t num_read;

    /**************************************************************************/

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
   
    if(server_fd == -1){
        perror("[ERR] Communications Layer: AF_UNIX socket() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    unlink(socket_path);

    /**************************************************************************/

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) 
         == -1
       ) 
    {
        perror("[ERR] Communications Layer: AF_UNIX bind() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    if(listen(server_fd, 5) == -1){
        perror("[ERR] Communications Layer: AF_UNIX listen() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    /**************************************************************************/

    // Accept a client connection
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd == -1) {
        perror("[ERR] Communications Layer: AF_UNIX accept() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    // Read data from client
    num_read = read(client_fd, buf, BUFFER_SIZE - 1);

    if (num_read > 0) {
        buf[num_read] = '\0'; // Null terminate
        printf("[OK] UNIX Server received %lu-byte msg: %s\n", num_read, buf);
    }
    else {
        perror("[ERR] Communications Layer: AF_UNIX read() call failed!\n");
        ret = 1;
        goto label_cleanup;
    }

    goto label_init_succeeded;

    /**************************************************************************/

label_cleanup:

    if(server_fd != -1)
        close(server_fd);

    unlink(socket_path);

label_init_succeeded:

    return ret;
}
