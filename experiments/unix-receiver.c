#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/uds_socket"
#define BUFFER_SIZE 1024

int main() {
    int server_socket, client_socket;
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];

    // Remove the socket file if it already exists
    unlink(SOCKET_PATH);

    // Create a UNIX domain stream socket
    server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the sockaddr_un structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Bind the socket to the address
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 1) == -1) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Receiver is waiting for a connection...\n");

    // Accept a client connection
    client_len = sizeof(client_addr);
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket == -1) {
        perror("accept");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Connection established with sender\n");

    // Receive the data
    ssize_t num_bytes;
    while ((num_bytes = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[num_bytes] = '\0'; // Null-terminate the received data
        printf("Received: %s\n", buffer);
    }

    if (num_bytes == -1) {
        perror("recv");
    }

    // Clean up
    close(client_socket);
    close(server_socket);
    unlink(SOCKET_PATH);

    return 0;
}
