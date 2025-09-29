#include <netinet/in.h>
#include <sys/un.h>

uint8_t init_client_interprocess_comms(char* required_socket_pathname){

    int unix_socket_fd = 0;
    int len            = 0;
    int sock_path_len  = 0;

    uint8_t ret = 0;
 
    struct sockaddr_un unix_server_addr;

    /**************************************************************************/

    unix_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(unix_socket_fd < 0){
        perror("[ERR] Communications Layer: AF_UNIX socket() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Communications Layer: AF_UNIX socket() call is OK.\n");

    /**************************************************************************/

    unix_server_addr.sun_family = AF_UNIX;
    sock_path_len = strlen(required_socket_pathname);
    strncpy(unix_server_addr.sun_path,required_socket_pathname,sock_path_len+1);
    len = sock_path_len + 1 + sizeof(unix_server_addr.sun_family);

    ret = connect(unix_socket_fd, (struct sockaddr*)&unix_server_addr, len)

    if(ret == -1){
        perror("[ERR] Communications Layer: AF_UNIX connect() call failed.\n");
        ret = 1;
        goto label_cleanup;
    }
    printf("[OK]  Communications Layer: AF_UNIX connect() call is OK.\n");
    
    /**************************************************************************/

    /* THIS SENDING IS FOR TESTING ONLY -- WONT BE IN FINAL VERSION! */

    if(write( unix_socket_fd
             ,"\n\n--->> Hello UNIX sockets! <<---\n\n"
             ,strlen("\n\n--->> Hello UNIX sockets! <<---\n\n")
            ) == -1
      )
    {
        perror("[ERR] Communications Layer: AF_UNIX test write() failed.\n");
        ret = 1;
        goto label_cleanup;
    }

    goto label_init_successful;

label_cleanup:

    if(unix_socket_fd >= 0)
        close(unix_socket_fd);

label_init_successful:

    return ret;
}
