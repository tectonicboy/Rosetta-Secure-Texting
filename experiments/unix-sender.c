#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/uds_socket"
#define MESSAGE "Hello from the sender!"

int main() {
    int client_socket;
    struct sockaddr_un server_addr;

    // Create a UNIX domain stream socket
    client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the sockaddr_un structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        perror("connect");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Send the message
    if (send(client_socket, MESSAGE, strlen(MESSAGE), 0) == -1) {
        perror("send");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Message sent: %s\n", MESSAGE);

    // Clean up
    close(client_socket);

    return 0;
}
