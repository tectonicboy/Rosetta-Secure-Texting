#include <sys/socket.h>
#include <sys/un.h>

#define PRIVKEY_LEN      40
#define PUBKEY_LEN       384
#define MAX_CLIENTS      64
#define MAX_PEND_MSGS    64
#define MAX_CHATROOMS    64
#define MAX_MSG_LEN      131072
#define MAX_TXT_LEN      1024
#define MAX_BIGINT_SIZ   12800
#define SMALL_FIELD_LEN  8
#define TEMP_BUF_SIZ     16384
#define SESSION_KEY_LEN  32
#define ONE_TIME_KEY_LEN 32
#define INIT_AUTH_LEN    32
#define SHORT_NONCE_LEN  12
#define LONG_NONCE_LEN   16
#define HMAC_TRUNC_BYTES 8

#define BUF_SIZ       100
#define SOCK_PATH     "/usr/bin/rosetta.sock\0"
#define SOCK_PATH_LEN strlen("/usr/bin/rosetta.sock\0")


uint8_t init_server_ipc_comms()
{
    uint8_t ret = 0;

    int server_fd;
    int client_fd;

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

    unlink(SOCK_PATH);

    /**************************************************************************/

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, SOCK_PATH_LEN + 1);
    
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

    sleep(1);

    // Read data from client
    num_read = read(client_fd, buf, BUF_SIZ - 1);

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

    unlink(SOCK_PATH);

label_init_succeeded:

    return ret;
}
